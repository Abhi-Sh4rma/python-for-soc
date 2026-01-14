from collections import Counter

LOG_FILE = "sample_logs/auth_sample.log"


def parse_failed_logins(file_path: str):
    """
    Reads a simple auth log file and counts FAILED_LOGIN events per user and per IP.
    """
    user_counter = Counter()
    ip_counter = Counter()
    total_failed = 0

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if "FAILED_LOGIN" in line:
                total_failed += 1

                # Example line format:
                # 2026-01-14 10:00:01 FAILED_LOGIN user=admin ip=192.168.1.10
                parts = line.split()

                for p in parts:
                    if p.startswith("user="):
                        user_counter[p.replace("user=", "")] += 1
                    if p.startswith("ip="):
                        ip_counter[p.replace("ip=", "")] += 1

    return total_failed, user_counter, ip_counter


if __name__ == "__main__":
    total, users, ips = parse_failed_logins(LOG_FILE)

    print("\n=== FAILED LOGIN SUMMARY ===")
    print(f"Log file: {LOG_FILE}")
    print(f"Total failed logins: {total}")

    print("\nTop users targeted:")
    for user, count in users.most_common():
        print(f"  {user}: {count}")

    print("\nTop source IPs:")
    for ip, count in ips.most_common():
        print(f"  {ip}: {count}")
