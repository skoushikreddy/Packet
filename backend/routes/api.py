"""
NetScope REST API Blueprints
Flask endpoints for interface discovery, capture control, history, and exports.
"""

import time
import io
import csv
from flask import Blueprint, jsonify, request, Response
from ..database import db
from ..analyzers.filter_parser import translate_filter_to_bpf
from ..capture.sniffer import ScapySnifferWorker

api_bp = Blueprint("api", __name__)


def setup_routes(sniffer_worker: ScapySnifferWorker, current_session_holder: dict):

    @api_bp.route("/interfaces", methods=["GET"])
    def get_interfaces():
        ifaces = ScapySnifferWorker.get_interfaces()
        return jsonify({"success": True, "interfaces": ifaces})

    @api_bp.route("/capture/start", methods=["POST"])
    def start_capture():
        data = request.get_json() or {}
        iface_name = data.get("interfaceName", "default")
        filter_expr = data.get("bpfFilter", "")

        is_valid, bpf_str, err = translate_filter_to_bpf(filter_expr)
        if not is_valid:
            return jsonify({"success": False, "error": f"Invalid filter: {err}"}), 400

        session_id = f"session_{int(time.time())}"
        start_ts = int(time.time() * 1000)

        started = sniffer_worker.start_capture(iface_name, bpf_str or "")
        if not started:
            return jsonify({"success": False, "error": "Capture already in progress"}), 400

        current_session_holder["id"] = session_id
        current_session_holder["startTime"] = start_ts
        current_session_holder["interfaceName"] = iface_name
        current_session_holder["bpfFilter"] = filter_expr

        db.create_session(session_id, f"Capture on {iface_name}", iface_name, start_ts, filter_expr)

        return jsonify({
            "success": True,
            "message": f"Capture started on {iface_name}",
            "session": {
                "id": session_id,
                "interfaceName": iface_name,
                "startTime": start_ts,
                "bpfFilter": filter_expr,
                "status": "running"
            }
        })

    @api_bp.route("/capture/stop", methods=["POST"])
    def stop_capture():
        if not sniffer_worker.is_capturing:
            return jsonify({"success": True, "message": "Capture not running"})

        sniffer_worker.stop_capture()
        session_id = current_session_holder.get("id")
        end_ts = int(time.time() * 1000)

        if session_id:
            db.update_session_stop(
                session_id,
                end_ts,
                sniffer_worker.total_packets,
                sniffer_worker.total_bytes
            )

        return jsonify({
            "success": True,
            "message": "Capture stopped",
            "session": {
                "id": session_id,
                "packetCount": sniffer_worker.total_packets,
                "totalBytes": sniffer_worker.total_bytes,
                "status": "stopped"
            }
        })

    @api_bp.route("/capture/status", methods=["GET"])
    def get_status():
        return jsonify({
            "success": True,
            "isCapturing": sniffer_worker.is_capturing,
            "sessionId": current_session_holder.get("id"),
            "interfaceName": sniffer_worker.selected_interface or "default",
            "packetCount": sniffer_worker.total_packets,
            "totalBytes": sniffer_worker.total_bytes,
            "startTime": current_session_holder.get("startTime", 0)
        })

    @api_bp.route("/history", methods=["GET"])
    def get_history():
        sessions = db.get_all_sessions()
        return jsonify({"success": True, "sessions": sessions})

    @api_bp.route("/history/<session_id>", methods=["GET"])
    def get_session_detail(session_id):
        sess = db.get_session_by_id(session_id)
        if not sess:
            return jsonify({"success": False, "error": "Session not found"}), 404
        return jsonify({"success": True, "session": sess})

    @api_bp.route("/history/<session_id>", methods=["DELETE"])
    def delete_session(session_id):
        success = db.delete_session(session_id)
        if not success:
            return jsonify({"success": False, "error": "Session not found"}), 404
        return jsonify({"success": True, "message": "Session deleted"})

    @api_bp.route("/export/csv", methods=["GET"])
    def export_csv():
        session_id = request.args.get("sessionId")
        packets = []
        if session_id:
            s_data = db.get_session_by_id(session_id)
            if s_data:
                packets = s_data.get("packets", [])

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["No.", "Time", "Source IP", "Destination IP", "Protocol", "Length", "Source Port", "Destination Port", "Info"])

        for p in packets:
            writer.writerow([
                p.get("packet_number") or p.get("id"),
                p.get("time_str") or p.get("timeStr"),
                p.get("src_ip") or p.get("srcIp"),
                p.get("dst_ip") or p.get("dstIp"),
                p.get("protocol"),
                p.get("length"),
                p.get("src_port") or p.get("srcPort") or "",
                p.get("dst_port") or p.get("dstPort") or "",
                p.get("info")
            ])

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=netscope_{session_id or 'export'}.csv"}
        )

    return api_bp
