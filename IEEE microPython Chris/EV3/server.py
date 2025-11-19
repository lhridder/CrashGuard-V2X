import socket
from flask import Flask, jsonify

last_device_name = None
app = Flask(__name__)

@app.route("/")
def home():
    # return HTML page with JavaScript to auto-update
    return """
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <title>EV3 Connected Device</title>
    </head>
    <body>
      <h1 id="device">No device connected</h1>
      <script>
        async function updateDevice() {
          try {
            const r = await fetch('/device');
            const data = await r.json();
            document.getElementById('device').textContent = data.device ? 
                'Connected: ' + data.device : 'No device connected';
          } catch (e) {
            console.error(e);
          }
        }
        setInterval(updateDevice, 1000);  // poll every 1 second
        updateDevice();  // initial fetch
      </script>
    </body>
    </html>
    """

@app.route("/device")
def device():
    return jsonify({"device": last_device_name})

def socket_server(host="0.0.0.0", port=5001):
    global last_device_name
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)
    print(f"Socket server listening on {host}:{port}")
    while True:
        conn, addr = sock.accept()
        data = conn.recv(1024).decode("utf-8").strip()
        if data:
            last_device_name = data
            print(f"Device connected: {data} from {addr}")
        conn.close()

if __name__ == "__main__":
    import threading
    threading.Thread(target=socket_server, daemon=True).start()
    print("Flask webserver on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000)