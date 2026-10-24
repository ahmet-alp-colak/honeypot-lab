import time
from collections import defaultdict, deque

LOGIN_WINDOW_SECONDS = 60
LOGIN_THRESHOLD = 10
SCAN_WINDOW_SECONDS = 30
SCAN_PATH_THRESHOLD = 15
LOGIN_ATTEMPTS = defaultdict(deque)
PATH_ATTEMPTS = defaultdict(deque)

def record_login_attempt(ip):
    now = time.monotonic()
    attempts = LOGIN_ATTEMPTS[ip]
    attempts.append(now)
    while attempts and now - attempts[0] > LOGIN_WINDOW_SECONDS:
        attempts.popleft()
    return len(attempts)

def is_bruteforce(ip):
    count = record_login_attempt(ip)
    return count >= LOGIN_THRESHOLD, count

def record_path_attempt(ip, path):
    now = time.monotonic()
    attempts = PATH_ATTEMPTS[ip]
    attempts.append((now, path))
    while attempts and now - attempts[0][0] > SCAN_WINDOW_SECONDS:
        attempts.popleft()
    return len({path for _, path in attempts})

def is_scanning(ip, path):
    count = record_path_attempt(ip, path)
    return count >= SCAN_PATH_THRESHOLD, count
