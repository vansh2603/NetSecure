
from datetime import datetime

from database.db import db
from database.models import Scan, Host, Port, Vulnerability
from risk_engine.vulnerability_matcher import match_vulnerabilities
from risk_engine.risk_calculator import calculate_risk


def save_scan_results(scan_id, report):
    scan = db.session.get(Scan, scan_id)

    if scan is None:
        raise ValueError(f"Scan ID {scan_id} was not found")

    target = report["target"]

    host = Host.query.filter_by(
        scan_id=scan.id,
        ip_address=target
    ).first()

    if host is None:
        host = Host(
            scan_id=scan.id,
            ip_address=target,
            hostname="localhost" if target == "127.0.0.1" else None,
            status="Up"
        )
        db.session.add(host)
        db.session.flush()

    all_findings = []
    saved_ports = 0

    for result in report["open_ports"]:
        port = Port.query.filter_by(
            host_id=host.id,
            port_number=result["port"],
            protocol=result["protocol"]
        ).first()

        if port is None:
            port = Port(
                host_id=host.id,
                port_number=result["port"],
                protocol=result["protocol"],
                state=result["state"],
                service=result["service"]
            )
            db.session.add(port)
            db.session.flush()
        else:
            port.state = result["state"]
            port.service = result["service"]

        saved_ports += 1

        findings = match_vulnerabilities(
            result["service"],
            result["port"]
        )

        for finding in findings:
            existing = Vulnerability.query.filter_by(
                port_id=port.id,
                name=finding["name"]
            ).first()

            if existing is None:
                existing = Vulnerability(
                    port_id=port.id,
                    name=finding["name"],
                    severity=finding["severity"],
                    score=finding["score"],
                    description=finding["description"],
                    recommendation=finding["recommendation"]
                )
                db.session.add(existing)
            else:
                existing.severity = finding["severity"]
                existing.score = finding["score"]
                existing.description = finding["description"]
                existing.recommendation = finding["recommendation"]

            all_findings.append(finding)

    scan.risk_score = calculate_risk(all_findings)
    scan.status = "Completed"
    scan.end_time = datetime.now()

    db.session.commit()

    return {
        "scan_id": scan.id,
        "host_id": host.id,
        "saved_open_ports": saved_ports,
        "vulnerabilities_found": len(all_findings),
        "risk_score": scan.risk_score,
        "status": scan.status
    }
