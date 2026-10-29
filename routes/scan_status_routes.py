from datetime import datetime
from flask import Blueprint, request, jsonify
from database.db import db
from database.models import Scan

scan_status_bp = Blueprint("scan_status", __name__)


@scan_status_bp.route("/api/scans/<int:scan_id>/status", methods=["PUT"])
def update_scan_status(scan_id):
    scan = Scan.query.get(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    data = request.get_json(silent=True) or {}
    status = data.get("status")

    allowed_statuses = ["Pending", "Running", "Completed", "Failed"]

    if status not in allowed_statuses:
        return jsonify({
            "error": "Invalid status",
            "allowed_statuses": allowed_statuses
        }), 400

    scan.status = status

    if status == "Running" and scan.start_time is None:
        scan.start_time = datetime.now()

    if status in ["Completed", "Failed"]:
        scan.end_time = datetime.now()

    db.session.commit()

    return jsonify({
        "message": "Scan status updated successfully",
        "scan_id": scan.id,
        "status": scan.status
    })