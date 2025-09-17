import pyshark
import netifaces
import ipaddress
import json
import requests
import base64
import argparse
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
import time
import re
from base64 import b64decode

# Logging setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.FileHandler('ids.log'), logging.StreamHandler()])

class Config:
    def __init__(self):
        self.api_ip = '192.168.2.132'
        self.api_port = '8080'
        self.rate_window = 60
        self.syn_threshold = 50
        self.udp_threshold = 100
        self.monitor_protocols = ['HTTP', 'FTP', 'TELNET']

class pckt(object):
    def __init__(self, sniff_timestamp: str = '', layer: str = '', srcPort: str = '', dstPort: str = '', ipSrc: str = '', ipDst: str = '', highest_layer: str = ''):
        self.sniff_timestamp = sniff_timestamp
        self.layer = layer
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.ipSrc = ipSrc
        self.ipDst = ipDst
        self.highest_layer = highest_layer

class apiServer(object):
    def __init__(self, ip: str, port: str):
        self.ip = ip
        self.port = port

class RateLimiter:
    def __init__(self, window: int = 60, syn_thresh: int = 50, udp_thresh: int = 100):
        self.window = window
        self.syn_thresh = syn_thresh
        self.udp_thresh = udp_thresh
        self.src_history = defaultdict(deque)

    def add_packet(self, src_ip: str, pkt_type: str):
        now = time.time()
        self.src_history[src_ip].append(now)
        while self.src_history[src_ip] and now - self.src_history[src_ip][0] > self.window:
            self.src_history[src_ip].popleft()
        count = len(self.src_history[src_ip])
        if (pkt_type == 'SYN' and count > self.syn_thresh) or (pkt_type == 'UDP' and count > self.udp_thresh):
            return f"RATE ALERT: {count} {pkt_type} from {src_ip} in {self.window}s"
        return None

def check_credentials(packet):
    if not hasattr(packet, 'tcp'):
        return None
    payload = packet.tcp.payload.replace(':', '').replace('|', '')
    try:
        payload_bytes = bytes.fromhex(payload) if ':' in payload else payload.encode('ascii', errors='ignore')
        payload_str = payload_bytes.decode('ascii', errors='ignore').lower()
    except:
        return None
    creds = {}
    if hasattr(packet, 'http') and hasattr(packet.http, 'authbasic') and packet.http.authbasic:
        try:
            decoded = b64decode(packet.http.authbasic).decode('utf-8')
            user_pass = decoded.split(':', 1)
            creds['http'] = f"User: {user_pass[0]}, Pass: {user_pass[1] if len(user_pass) > 1 else 'N/A'}"
        except:
            pass
    elif packet.tcp.dstport == '21':
        if 'user' in payload_str:
            match = re.search(r'user\s+(\w+)', payload_str, re.I)
            if match:
                creds['ftp_user'] = match.group(1)
        if 'pass' in payload_str:
            match = re.search(r'pass\s+(\S+)', payload_str, re.I)
            if match:
                creds['ftp_pass'] = match.group(1)
    elif packet.tcp.dstport == '23' and ('password' in payload_str or 'login' in payload_str):
        lines = payload_str.split('\n')
        for line in lines:
            if any(kw in line for kw in ['pass:', 'login:']) and len(line.strip()) > 5:
                creds['telnet'] = line.strip()
    if creds:
        return f"CREDS: {creds} from {packet.ip.src}:{packet.tcp.srcport}"
    return None

# Argparse and init
parser = argparse.ArgumentParser()
parser.add_argument('--ip', default='192.168.2.132')
parser.add_argument('--port', default='8080')
args = parser.parse_args()
config = Config()
config.api_ip = args.ip
config.api_port = args.port
server = apiServer(config.api_ip, config.api_port)
rate_limiter = RateLimiter(config.rate_window, config.syn_threshold, config.udp_threshold)

def is_api_server(packet, server):
    if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
        if (packet.ip.src == server.ip or packet.ip.dst == server.ip) and \
           (packet.tcp.dstport == server.port or packet.tcp.srcport == server.port):
            return True
    return False

def is_private_ip(ip_address):
    ip = ipaddress.ip_address(ip_address)
    return ip.is_private

def packetFilter(packet):
    if is_api_server(packet, server):
        return
    if hasattr(packet, 'icmp'):
        p = pckt(ipSrc=packet.ip.src, ipDst=packet.ip.dst, highest_layer=packet.highest_layer)
        report(p)
        return
    if packet.transport_layer in ['TCP', 'UDP']:
        if hasattr(packet, 'ipv6'):
            if packet.ipv6.src.startswith(('fe80:', 'fc00:')) and packet.ipv6.dst.startswith(('fe80:', 'fc00:')):
                p = pckt(ipSrc=packet.ipv6.src, ipDst=packet.ipv6.dst, layer=packet.transport_layer,
                         highest_layer=packet.highest_layer, sniff_timestamp=packet.sniff_timestamp)
                if hasattr(packet, 'udp'):
                    p.srcPort, p.dstPort = packet.udp.srcport, packet.udp.dstport
                elif hasattr(packet, 'tcp'):
                    p.srcPort, p.dstPort = packet.tcp.srcport, packet.tcp.dstport
                report(p)
            return
        if hasattr(packet, 'ip') and is_private_ip(packet.ip.src) and is_private_ip(packet.ip.dst):
            p = pckt(ipSrc=packet.ip.src, ipDst=packet.ip.dst, layer=packet.transport_layer,
                     highest_layer=packet.highest_layer, sniff_timestamp=packet.sniff_timestamp)
            if hasattr(packet, 'udp'):
                p.srcPort, p.dstPort = packet.udp.srcport, packet.udp.dstport
            elif hasattr(packet, 'tcp'):
                p.srcPort, p.dstPort = packet.tcp.srcport, packet.tcp.dstport
            
            cred_alert = check_credentials(packet)
            if cred_alert:
                p.highest_layer = 'CREDENTIALS'
                report(p, 'creds')
                logging.critical(cred_alert)
                return
            
            if hasattr(packet, 'tcp') and packet.tcp.flags_syn == '1':
                rate_alert = rate_limiter.add_packet(packet.ip.src, 'SYN')
            elif hasattr(packet, 'udp'):
                rate_alert = rate_limiter.add_packet(packet.ip.src, 'UDP')
            if rate_alert:
                p.highest_layer = 'RATE_LIMIT'
                report(p, 'rate')
                logging.warning(rate_alert)
                return
            
            report(p)

def report(message: pckt, alert_type: str = 'info'):
    temp = json.dumps(message.__dict__)
    b64 = base64.b64encode(temp.encode('ascii')).decode('utf8')
    logging.info(f"Report {alert_type}: {temp}")
    try:
        requests.get(f'http://{server.ip}:{server.port}/api/?{b64}', timeout=5)
    except Exception as e:
        logging.error(f"Report failed: {e}")

intF = netifaces.gateways()['default'][netifaces.AF_INET][1]
capture = pyshark.LiveCapture(interface=intF, only_summaries=False, display_filter='tcp or udp or icmp')
try:
    for packet in capture.sniff_continuously():
        packetFilter(packet)
except KeyboardInterrupt:
    logging.info("Stopped by user")
finally:
    capture.close()
    logging.info("Capture closed")