
from flask import Blueprint, jsonify
from database.db import db
from database.models import Scan
from risk_engine.risk_calculator import get_risk_level

result_bp = Blueprint("result", __name__)


@result_bp.route("/api/results/<int:scan_id>", methods=["GET"])
def get_results(scan_id):
    scan = db.session.get(Scan, scan_id)

    if scan is None:
        return jsonify({
            "error": "Scan not found"
        }), 404

    results = []

    for host in scan.hosts:
        for port in host.ports:
            vulnerabilities = []

            for vulnerability in port.vulnerabilities:
                vulnerabilities.append({
                    "name": vulnerability.name,
                    "severity": vulnerability.severity,
                    "score": vulnerability.score,
                    "description": vulnerability.description,
                    "recommendation": vulnerability.recommendation
                })

            results.append({
                "host": host.ip_address,
                "port": port.port_number,
                "protocol": port.protocol,
                "state": port.state,
                "service": port.service,
                "vulnerabilities": vulnerabilities
            })

    risk_score = scan.risk_score
    risk_level = get_risk_level(risk_score)

    return jsonify({
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "total_ports_found": len(results),
        "results": results
    })


if __name__ == "__main__":
    print("Results route module loaded successfully")
