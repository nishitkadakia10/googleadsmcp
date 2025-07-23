"""
Simple health check endpoint for Railway
"""
from flask import Flask, jsonify
import threading
import os

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({
        "status": "healthy",
        "service": "google-ads-mcp-sse",
        "transport": "sse"
    })

@app.route('/health')
def health():
    return jsonify({"status": "ok"})

def run_health_server():
    """Run health check server on a different port"""
    health_port = int(os.environ.get("HEALTH_PORT", "8001"))
    app.run(host='0.0.0.0', port=health_port, debug=False)

# Start health server in a separate thread
if __name__ == "__main__":
    health_thread = threading.Thread(target=run_health_server)
    health_thread.daemon = True
    health_thread.start()
