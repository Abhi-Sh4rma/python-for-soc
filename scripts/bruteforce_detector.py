from collections import defaultdict
from datetime import datetime

LOG_FILE = "sample_logs/auth_sample.log"

# If a user has >= 3 failed logins within this time window, raise an alert
THRESHOLD = 3
WINDOW_SECONDS = 60


def parse_time(ts: str) -> datetime:
    # Format: 2026-01-14 10:00:01
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


def detect_bruteforce(file_path: str):
    """
    Detects brute-force-like behavior:
    Many FAILED_LOGIN attempts for the same user within a short time window.
    """
    failed_attempts = defaultdict(list)

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if "FAILED_LOGIN" not in line:
                continue

            # Example:
            # 2026-01-14 10:00:01 FAILED_LOGIN user=admin ip=192.168.1.10
            parts = line.split()

            timestamp = parse_time(parts[0] + " " + parts[1])

            user = None
            ip = None

            for p in parts:
                if p.startswith("user="):
                    user = p.replace("user=", "")
                if p.startswith("ip="):
                    ip = p.replace("ip=", "")

            if user:
                failed_attempts[user].append((timestamp, ip))

    alerts = []

    for user, attempts in failed_attempts.items():
        attempts.sort(key=lambda x: x[0])

        # sliding window check
        for i in range(len(attempts)):
            start_time = attempts[i][0]
            count = 1

            for j in range(i + 1, len(attempts)):
                diff = (attempts[j][0] - start_time).total_seconds()
                if diff <= WINDOW_SECONDS:
                    count += 1
                else:
                    break

            if count >= THRESHOLD:
                alerts.append((user, count, start_time))
                break

    return alerts


if __name__ == "__main__":
    alerts = detect_bruteforce(LOG_FILE)

    print("\n=== BRUTE FORCE DETECTOR ===")
    print(f"Log file: {LOG_FILE}")
    print(f"Rule: {THRESHOLD}+ failed logins within {WINDOW_SECONDS}s\n")

    if not alerts:
        print("✅ No brute force behavior detected.")
    else:
        for user, count, start_time in alerts:
            print(f"🚨 ALERT: Possible brute force on user '{user}'")
            print(f"   Failed attempts: {count}")
            print(f"   Window started: {start_time}")
