from flask import Blueprint, request, jsonify
from database.db import db
from database.models import Scan

risk_bp = Blueprint("risk", __name__)


@risk_bp.route("/api/scans/<int:scan_id>/risk", methods=["PUT"])
def update_risk_score(scan_id):
    scan = Scan.query.get(scan_id)

    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    data = request.get_json()
    risk_score = data.get("risk_score")

    if risk_score is None:
        return jsonify({"error": "Risk score is required"}), 400

    try:
        risk_score = float(risk_score)
    except (TypeError, ValueError):
        return jsonify({"error": "Risk score must be a number"}), 400

    if risk_score < 0 or risk_score > 10:
        return jsonify({"error": "Risk score must be between 0 and 10"}), 400

    scan.risk_score = risk_score
    db.session.commit()

    return jsonify({
        "message": "Risk score updated successfully",
        "scan_id": scan.id,
        "risk_score": scan.risk_score
    })