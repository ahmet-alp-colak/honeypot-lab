# Honeypot Lab

A modular, Flask-based **web honeypot** for collecting HTTP attack telemetry and detecting common suspicious behaviors. The project is an educational security research lab and an evolving foundation for additional honeypot services.

> **Status:** Active development. The web module is implemented; SSH support, a dashboard, and persistent detection state are planned, not yet available.

## Features

- **Configurable decoy endpoints:** Define fake HTTP routes, templates, and event names in `core/config.json`.
- **Structured telemetry:** Write newline-delimited JSON (NDJSON) events to `logs/attacks.json`.
- **Payload pattern analysis:** Heuristic detection of SQL injection (SQLi), local file inclusion/path traversal (LFI), remote command execution indicators (RCE), and cross-site scripting (XSS).
- **Risk scoring:** Assign a basic additive score based on matched attack categories. Scores are heuristic, not calibrated threat probabilities.
- **Brute-force detection:** Flag 10 login attempts from one IP within a 60-second sliding window.
- **Directory scan detection:** Flag 15 distinct paths from one IP within a 30-second sliding window.
- **Sensitive path probes:** Recognize requests targeting paths such as `/.env`, `.git`, and `phpmyadmin`.
- **Session correlation:** Associate requests with a Flask session-based `attacker_id` when cookies are retained.

## Project structure

```text
honeypot-lab/
├── core/
│   ├── __init__.py
│   ├── config.json
│   └── logger.py
├── services/
│   ├── __init__.py
│   └── web/
│       ├── __init__.py
│       ├── analyzer.py
│       ├── behavior.py
│       └── web_honeypot.py
├── templates/
│   ├── 404.html
│   ├── admin.html
│   ├── login.html
│   └── vulnerable.html
├── static/
├── logs/                  # runtime data; excluded from Git
├── requirements.txt
└── README.md
```

An archived `web_honeypot_original.py` may be present in restored copies; it is not the active entry point.

## Requirements

- Python 3.10+
- Flask 2.2–3.x (see `requirements.txt`)

## Local installation

```bash
git clone https://github.com/ahmet-alp-colak/honeypot-lab.git
cd honeypot-lab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export HONEYPOT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python -m services.web.web_honeypot
```

The development server listens on `http://127.0.0.1:5000` by default. Do not expose Flask's development server directly to the public Internet.

## Configuration

Add decoy routes in `core/config.json`:

```json
{
  "fake_endpoints": [
    {"path": "/admin", "template": "admin.html", "event": "admin_access"},
    {"path": "/search", "template": "vulnerable.html", "event": "search_query"}
  ]
}
```

Templates must exist in the top-level `templates/` directory. The active app also supports `HONEYPOT_CONFIG` to select a different JSON config file. Restart the app after editing configuration.

## Testing the detections

Run the application in one terminal and use another terminal for these **localhost-only** checks.

**SQLi-like search input:**

```bash
curl -G --data-urlencode "q=' UNION SELECT username,password FROM users" http://127.0.0.1:5000/search
```

**Repeated login attempts:**

```bash
for i in $(seq 1 10); do
  curl -s -X POST -d "username=demo&password=example$i" http://127.0.0.1:5000/login >/dev/null
done
```

**Path enumeration:**

```bash
for i in $(seq 1 15); do
  curl -s "http://127.0.0.1:5000/probe$i" >/dev/null
done
```

The brute-force test must complete within 60 seconds and the scan test within 30 seconds. Random response delays may affect timing. Detection events can be inspected with:

```bash
grep -E '"event": "(attack_detected|bruteforce_detected|scan_detected)"' logs/attacks.json
```

## Telemetry

Events include a timestamp, service, event type, source IP, and event-specific data. Examples of event types include:

`http_request`, `login_attempt`, `cmd_attempt`, `404_probe`, `sensitive_probe_detected`, `attack_detected`, `bruteforce_detected`, and `scan_detected`.

The logger currently writes JSON objects one per line into `logs/attacks.json`. Despite the filename, the file is **NDJSON**, not one JSON array.

## Limitations

- Signature matching is intentionally simple and can produce false positives or miss encoded/obfuscated payloads.
- Brute-force and scan tracking are **in-memory, per-process**, and reset on restart. Threshold alerting can repeat at the boundary under some request patterns.
- IP detection uses the direct peer address (`request.remote_addr`); trusted reverse-proxy configuration is not yet implemented.
- Session IDs are cookie-dependent and are not stable device fingerprints.
- The current logger has no rotation, retention policy, or multi-process write coordination.
- Example HTML templates are basic placeholders, not production-quality decoys.
- No automated test suite is included yet.

## Security and responsible use

**Use only in isolated, authorized environments.** A honeypot receives untrusted input and may capture sensitive data. Do not direct traffic to third-party systems, reuse real credentials, or deploy on a production host without isolation and a deployment review. Keep logs private: login submissions are currently stored in plaintext, including password fields. Do not commit `.env` files, secrets, or collected logs. Set `HONEYPOT_SECRET` explicitly and restrict access to runtime data.

## Roadmap

- [ ] Automated tests for detection thresholds and route behavior
- [ ] Alert cooldown and event correlation
- [ ] Improved normalization and signature coverage
- [ ] Safer, rotating log storage and configurable retention
- [ ] Persistent behavioral state (SQLite or Redis)
- [ ] Configurable detection thresholds
- [ ] SSH honeypot service
- [ ] Dashboard and telemetry visualization

## License

No license has been selected yet. Until one is added, normal copyright restrictions apply. Choose an explicit open-source license if you want to permit reuse and contributions.
