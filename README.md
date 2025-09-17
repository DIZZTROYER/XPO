 XPO
 
A Python Based IDS that inspects live Wi-Fi traffic, looks for cleartext credential leaks, applies  rate-limiting and alerting, and safely reports incidents.

Features
- Credential Detection:Identifies plaintext credentials in HTTP, FTP, and Telnet traffic.
- Rate Limiting Detection: Flags excessive SYN or UDP packets (e.g., potential scans or floods) based on configurable thresholds.
- Real-Time Monitoring: Continuously sniffs packets on the default network interface.
- Logging: Records all events to ids.log with fallback to local_log.txt if the API fails.
- Configurable: Supports custom API IP and port via environment variables or command-line arguments.

Requirements.
- Python 3.8+
- Installed Packages: 
  - pyshark (requires Wireshark with tshark installed)
  - netifaces
  - requests
  - flask (for the API server)
- System Dependencies:
  - Windows: Microsoft C++ Build Tools, Npcap (for promiscuous mode)
  - Run as Administrator for packet capturing
- Hardware: WiFi adapter (monitor mode supported for full network visibility, optional)

 Installation
1. Clone the repository:

   git clone https://github.com/DIZZTROYER/XPO
   cd XPO
   
2. Create a virtual environment and activate it

3. Install dependencies:
   pip install -r requirements.txt

   
To run the IDS, set the API server IP in a .env file or via the --ip argument (e.g., python XPO.py --ip 127.0.0.1). Ensure a Flask server is running at that address.

Usuage:

1.Start the API server on the configured IP/port:
  python api_server.py

2.Run the IDS script:
  python XPO.py

3.Ping: ping 127.0.0.1
  HTTP with creds: curl -u user:pass http://localhost:8000 (run python -m http.server first)
