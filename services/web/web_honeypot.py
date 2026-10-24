import os
import random
import time
import uuid
from pathlib import Path
from flask import Flask, json, request, render_template, session
from core.logger import log_event
from services.web.analyzer import analyze
from services.web.behavior import is_bruteforce, is_scanning, LOGIN_WINDOW_SECONDS, SCAN_WINDOW_SECONDS

PROJECT_ROOT = Path(__file__).resolve().parents[2]
app = Flask(__name__, template_folder=str(PROJECT_ROOT / "templates"), static_folder=str(PROJECT_ROOT / "static"))
app.secret_key = os.environ.get("HONEYPOT_SECRET", "dev_insecure_key")
config_path = Path(os.environ.get("HONEYPOT_CONFIG", str(PROJECT_ROOT / "core" / "config.json")))
with config_path.open(encoding="utf-8") as f:
    CONFIG = json.load(f)

def get_real_ip():
    # Do not trust X-Forwarded-For without a configured trusted reverse proxy.
    return request.remote_addr or "unknown"

def human_delay():
    time.sleep(random.uniform(0.2, 1.2))

def log(event_type, data=None):
    ip = get_real_ip()
    payload = dict(data or {})
    payload["attacker_id"] = session.get("attacker_id")
    analysis = analyze(payload)
    if analysis:
        log_event("web", "attack_detected", ip, {**analysis, "attacker_id": session.get("attacker_id")})
    log_event("web", event_type, ip, payload)

@app.before_request
def track_attacker():
    if "attacker_id" not in session:
        session["attacker_id"] = uuid.uuid4().hex[:12]
    if request.path.startswith("/static/"):
        return
    ip = get_real_ip()
    scanning, unique_count = is_scanning(ip, request.path)
    # Emit once at threshold crossing to avoid a flood of alerts.
    from services.web.behavior import SCAN_PATH_THRESHOLD
    if scanning and unique_count == SCAN_PATH_THRESHOLD:
        log_event("web", "scan_detected", ip, {"unique_paths_in_window": unique_count, "window_seconds": SCAN_WINDOW_SECONDS})
    log("http_request", {"path": request.path, "method": request.method, "user_agent": request.headers.get("User-Agent"), "referer": request.headers.get("Referer"), "args": request.args.to_dict()})

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    human_delay()
    ip = get_real_ip()
    username = request.form.get("username")
    password = request.form.get("password")
    bruteforce, count = is_bruteforce(ip)
    from services.web.behavior import LOGIN_THRESHOLD
    if bruteforce and count == LOGIN_THRESHOLD:
        log_event("web", "bruteforce_detected", ip, {"attempts_in_window": count, "window_seconds": LOGIN_WINDOW_SECONDS})
    log("login_attempt", {"username": username, "password": password, "user_agent": request.headers.get("User-Agent")})
    return random.choice(["Invalid credentials.", "Account locked.", "Too many attempts.", "Authentication failed."])

@app.route("/cmd")
def cmd():
    human_delay()
    log("cmd_attempt", {"command": request.args.get("command"), "user_agent": request.headers.get("User-Agent")})
    return "Command execution is not allowed."

def create_fake_endpoint(path, template, event_name):
    endpoint_name = f"fake_{event_name}_{path.replace('/', '_')}"
    def endpoint():
        human_delay()
        data = {}
        if event_name == "search_query":
            data["query"] = request.args.get("q")
        log(event_name, data)
        return render_template(template)
    app.add_url_rule(path, endpoint_name, endpoint)

for ep in CONFIG.get("fake_endpoints", []):
    create_fake_endpoint(ep["path"], ep["template"], ep["event"])

COMMON_PROBES = ["phpmyadmin", "wp-", ".env", "backup", ".git", "config"]

@app.errorhandler(404)
def page_not_found(e):
    human_delay()
    event = "sensitive_probe_detected" if any(p in request.path.lower() for p in COMMON_PROBES) else "404_probe"
    log(event, {"path": request.path})
    return render_template("404.html"), 404

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
