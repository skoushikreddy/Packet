"""
NetScope — Python Flask & Scapy Backend Application
Academic Computer Networks Project
"""

import os
from flask import Flask
from flask_cors import CORS
from flask_socketio import SocketIO
from .database import db
from .capture.sniffer import ScapySnifferWorker
from .routes.api import setup_routes

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# State holders
current_session_holder = {}


def on_packet_captured(packet_summary):
    # Store to SQLite
    session_id = current_session_holder.get("id")
    if session_id:
        db.insert_packet(session_id, packet_summary)

    # Broadcast to WebSocket clients
    socketio.emit("packet", packet_summary)


# Initialize components
db.init_db()
sniffer_worker = ScapySnifferWorker(on_packet_captured)
api_blueprint = setup_routes(sniffer_worker, current_session_holder)
app.register_blueprint(api_blueprint, url_prefix="/api")


@socketio.on("connect")
def handle_connect():
    socketio.emit("status", {
        "isCapturing": sniffer_worker.is_capturing,
        "sessionId": current_session_holder.get("id"),
        "packetCount": sniffer_worker.total_packets,
        "totalBytes": sniffer_worker.total_bytes,
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] NetScope Python Backend listening on http://0.0.0.0:{port}")
    socketio.run(app, host="0.0.0.0", port=port, debug=False)
