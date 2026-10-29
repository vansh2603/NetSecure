from routes.risk_routes import risk_bp
from routes.scan_status_routes import scan_status_bp
from routes.result_routes import result_bp
from routes.vulnerability_routes import vulnerability_bp
from routes.dashboard_routes import dashboard_bp
from flask import Flask, render_template
from database.db import db
from database.models import Scan
from routes.scan_routes import scan_bp
from routes.report_routes import report_bp

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///netsecure.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.register_blueprint(risk_bp)
app.register_blueprint(scan_status_bp)
app.register_blueprint(result_bp)
app.register_blueprint(vulnerability_bp)
db.init_app(app)
app.register_blueprint(scan_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(report_bp)

with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)