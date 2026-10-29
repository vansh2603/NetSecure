from database.db import db



from datetime import datetime
from database.db import db


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(100), nullable=False)
    status = db.Column(
        db.String(50),
        nullable=False,
        default="Pending"
    )
    risk_score = db.Column(
        db.Float,
        nullable=False,
        default=0.0
    )
    start_time = db.Column(
        db.DateTime,
        default=datetime.now
    )
    end_time = db.Column(db.DateTime)

    hosts = db.relationship(
        "Host",
        backref="scan",
        lazy=True,
        cascade="all, delete-orphan"
    )

class Host(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scan.id"), nullable=False)
    ip_address = db.Column(db.String(100), nullable=False)
    hostname = db.Column(db.String(100))
    status = db.Column(db.String(50))

    ports = db.relationship("Port", backref="host", lazy=True)


class Port(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey("host.id"), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(20), default="TCP")
    state = db.Column(db.String(20))
    service = db.Column(db.String(100))

    vulnerabilities = db.relationship(
        "Vulnerability",
        backref="port",
        lazy=True
    )


class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    port_id = db.Column(db.Integer, db.ForeignKey("port.id"), nullable=False)
    name = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(50))
    score = db.Column(db.Float, default=0.0)
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)