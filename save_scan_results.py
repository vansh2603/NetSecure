
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
    else:
        host.status = "Up"

    open_ports = report.get("open_ports", [])
    current_port_keys = {
        (item["port"], item.get("protocol", "TCP"))
        for item in open_ports
    }

    for old_port in list(host.ports):
        key = (old_port.port_number, old_port.protocol)
        if key not in current_port_keys:
            db.session.delete(old_port)

    all_findings = []
    saved_ports = 0

    for result in open_ports:
        protocol = result.get("protocol", "TCP")
        port_number = result["port"]

        port = Port.query.filter_by(
            host_id=host.id,
            port_number=port_number,
            protocol=protocol
        ).first()

        if port is None:
            port = Port(
                host_id=host.id,
                port_number=port_number,
                protocol=protocol
            )
            db.session.add(port)
            db.session.flush()

        port.state = result.get("state", "Open")
        port.service = result.get("service", "Unknown")

        findings = match_vulnerabilities(port.service, port.port_number)
        current_finding_names = {item["name"] for item in findings}

        for old_finding in list(port.vulnerabilities):
            if old_finding.name not in current_finding_names:
                db.session.delete(old_finding)

        for finding in findings:
            vulnerability = Vulnerability.query.filter_by(
                port_id=port.id,
                name=finding["name"]
            ).first()

            if vulnerability is None:
                vulnerability = Vulnerability(
                    port_id=port.id,
                    name=finding["name"]
                )
                db.session.add(vulnerability)

            vulnerability.severity = finding["severity"]
            vulnerability.score = finding["score"]
            vulnerability.description = finding["description"]
            vulnerability.recommendation = finding["recommendation"]

            all_findings.append(finding)

        saved_ports += 1

    db.session.flush()

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
