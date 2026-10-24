import json
import re

PATTERN_MAP = {
    "sqli": [r"union\s+select", r"or\s+1=1", r"information_schema", r"sleep\(", r"benchmark\("],
    "lfi": [r"\.\./", r"/etc/passwd", r"/proc/self/environ"],
    "rce": [r";\s*ls", r";\s*whoami", r"\|\s*id", r"cmd="],
    "xss": [r"<script>", r"onerror=", r"javascript:"],
}
WEIGHTS = {"sqli": 5, "lfi": 4, "rce": 6, "xss": 3}

def normalize_payload(data):
    try:
        return json.dumps(data, ensure_ascii=False).lower()
    except (TypeError, ValueError):
        return str(data).lower()

def detect_patterns(raw):
    findings = {}
    for attack_type, patterns in PATTERN_MAP.items():
        for pattern in patterns:
            if re.search(pattern, raw):
                findings.setdefault(attack_type, []).append(pattern)
    return findings

def risk_score(findings):
    return sum(WEIGHTS.get(kind, 1) for kind in findings)

def analyze(data):
    findings = detect_patterns(normalize_payload(data))
    if not findings:
        return None
    return {"attack_types": list(findings), "indicators": findings, "risk_score": risk_score(findings)}
