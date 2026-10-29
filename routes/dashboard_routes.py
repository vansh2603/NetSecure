from flask import Blueprint, jsonify
from database.models import Scan

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/api/dashboard", methods=["GET"])
def dashboard():
    total_scans = Scan.query.count()

    completed_scans = Scan.query.filter_by(status="Completed").count()

    pending_scans = Scan.query.filter_by(status="Pending").count()

    return jsonify({
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "pending_scans": pending_scans
    })