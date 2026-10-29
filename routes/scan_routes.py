
from datetime import datetime
from flask import Blueprint, request, jsonify

from database.db import db
from database.models import Scan
from scanner.scanner_engine import run_scan
from scanner.save_scan_results import save_scan_results

scan_bp = Blueprint("scan", __name__)


@scan_bp.route("/api/scan", methods=["POST"])
def create_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("target")

    if target != "127.0.0.1":
        return jsonify({
            "error": "For this development version, target must be 127.0.0.1"
        }), 400

    scan = Scan(
        target=target,
        status="Running",
        risk_score=0.0,
        start_time=datetime.now()
    )

    try:
        db.session.add(scan)
        db.session.commit()

        report = run_scan(target)
        save_result = save_scan_results(scan.id, report)

        return jsonify({
            "message": "Scan completed successfully",
            "scan_id": scan.id,
            "target": target,
            "status": "Completed",
            "total_ports_checked": report["total_ports_checked"],
            "open_ports": report["open_ports"],
            "saved_results": save_result
        }), 201

    except Exception:
        db.session.rollback()

        scan.status = "Failed"
        scan.end_time = datetime.now()
        db.session.commit()

        return jsonify({
            "error": "Scan failed. Check the Flask terminal for details.",
            "scan_id": scan.id,
            "status": scan.status
        }), 500


@scan_bp.route("/api/scans", methods=["GET"])
def get_scans():
    scans = Scan.query.order_by(Scan.id.desc()).all()

    return jsonify([
        {
            "id": scan.id,
            "target": scan.target,
            "status": scan.status,
            "risk_score": scan.risk_score
        }
        for scan in scans
    ])


@scan_bp.route("/api/scans/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    scan = db.session.get(Scan, scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    return jsonify({
        "id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "risk_score": scan.risk_score
    })
