import os
import uuid
import time
import random
from flask import Flask, json, request, render_template, session
from core.logger import log_event

app = Flask(__name__, template_folder="../templates", static_folder="../static")
app.secret_key = "prod_fake_key_2026_very_secure"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
config_path = os.path.join(BASE_DIR, "..", "core", "config.json")
# ----------------------------------
# Load config
# ----------------------------------
with open(config_path) as f:
    CONFIG = json.load(f)

# -----------------------------
# utils
# -----------------------------

def get_real_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr

def human_delay():
    time.sleep(random.uniform(0.2, 1.2))

def log(event_type, data=None):
    ip = get_real_ip()
    attacker_id = session.get("attacker_id")

    payload = data or {}
    payload["attacker_id"] = attacker_id

    log_event("web", event_type, ip, payload)

# -----------------------------
# tracking
# -----------------------------

@app.before_request
def track_attacker():
    if "attacker_id" not in session:
        session["attacker_id"] = uuid.uuid4().hex[:12]

    #LOgging the staticks
    if request.path.startswith("/static"):
        return

    log("http_request", {
        "path": request.path,
        "method": request.method,
        "user_agent": request.headers.get("User-Agent"),
        "referer": request.headers.get("Referer"),
        "args": request.args.to_dict()
    })

# -----------------------------
# routes
# -----------------------------

@app.route("/")
def home():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    human_delay()

    username = request.form.get("username")
    password = request.form.get("password")

    log("login_attempt", {
        "username": username,
        "password": password,
        "user_agent": request.headers.get("User-Agent")
    })

    responses = [
        "Invalid credentials.",
        "Account locked.",
        "Too many attempts.",
        "Authentication failed."
    ]

    return random.choice(responses)

@app.route("/cmd")
def cmd():
    human_delay()

    log("cmd_attempt", {
        "command": request.args.get("command"),
        "user_agent": request.headers.get("User-Agent")
    })

    return "Command execution is not allowed."

# ----------------------------------
# 🔥 CONFIG TABANLI FAKE ENDPOINTLER
# ----------------------------------
def create_fake_endpoint(path, template, event_name):

    def endpoint():
        human_delay()

        data = {}

        if event_name == "search_query":
            data["query"] = request.args.get("q")

        log(event_name, data)

        return render_template(template)

    app.add_url_rule(path, path, endpoint)

for ep in CONFIG.get("fake_endpoints", []):
    create_fake_endpoint(
        ep["path"],
        ep["template"],
        ep["event"]
    )

@app.errorhandler(404)
def page_not_found(e):
    human_delay()

    log("404_probe", {
        "path": request.path
    })

    return render_template("404.html"), 404

# -----------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
