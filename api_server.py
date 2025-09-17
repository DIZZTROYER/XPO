from flask import Flask, request
app = Flask(__name__)

@app.route('/api/')
def api():
    payload = request.args.get('payload', 'No data')
    with open('api_log.txt', 'a') as f:
        f.write(f"{payload}\n")
    return "OK", 200

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)  # Bind to all interfaces