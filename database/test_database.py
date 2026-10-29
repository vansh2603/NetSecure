import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app
from database.db import db
from database.models import Scan, Host, Port, Vulnerability

with app.app_context():

    scan = Scan(
        target="127.0.0.1",
        status="Completed",
        risk_score=5.5
    )
    db.session.add(scan)
    db.session.commit()

    host = Host(
        scan_id=scan.id,
        ip_address="127.0.0.1",
        hostname="localhost",
        status="Up"
    )
    db.session.add(host)
    db.session.commit()

    port = Port(
        host_id=host.id,
        port_number=445,
        protocol="TCP",
        state="Open",
        service="SMB"
    )
    db.session.add(port)
    db.session.commit()

    vulnerability = Vulnerability(
        port_id=port.id,
        name="SMB Service Exposure",
        severity="Medium",
        score=5.5,
        description="SMB service is exposed on the target host.",
        recommendation="Restrict SMB access and allow it only for authorized systems."
    )
    db.session.add(vulnerability)
    db.session.commit()

    print("Database test completed successfully!")
    print("Scan ID:", scan.id)
    print("Host ID:", host.id)
    print("Port ID:", port.id)
    print("Vulnerability ID:", vulnerability.id)