import json
import re
import sys
from pathlib import Path
from collections import defaultdict

import pandas as pd

BASE = Path.home() / "adaptive-honeypot"
LOG_FILE = Path(sys.argv[1]).expanduser() if len(sys.argv) > 1 else BASE / "cowrie-lab/var/log/cowrie/cowrie.json"
REPORT_DIR = BASE / "reports"

# Patterns are indicators for review, not proof of malicious intent.
SUSPICIOUS_PATTERNS = {
    "system reconnaissance": r"\b(whoami|id|uname|hostname|ifconfig|ip addr)\b",
    "file or account discovery": r"\b(cat /etc/passwd|/etc/shadow|find /|history)\b",
    "download attempt": r"\b(wget|curl)\b",
    "permission or privilege change": r"\b(sudo|chmod|chown)\b",
}

def main():
    if not LOG_FILE.exists():
        raise SystemExit(f"Log file not found: {LOG_FILE}")

    events = []
    with LOG_FILE.open(encoding="utf-8") as f:
        for number, line in enumerate(f, 1):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"Warning: skipped invalid JSON on line {number}")

    if not events:
        raise SystemExit("No events found in the Cowrie log.")

    by_ip = defaultdict(list)
    for event in events:
        ip = event.get("src_ip", "unknown")
        by_ip[ip].append(event)

    results = []
    for ip, rows in by_ip.items():
        failed = sum(e.get("eventid") == "cowrie.login.failed" for e in rows)
        successful = sum(e.get("eventid") == "cowrie.login.success" for e in rows)

        usernames = sorted({
            str(e["username"]) for e in rows
            if e.get("username") and e.get("eventid") in {
                "cowrie.login.failed", "cowrie.login.success"
            }
        })

        commands = [
            str(e.get("input", "")).strip()
            for e in rows
            if e.get("eventid") == "cowrie.command.input"
            and e.get("input")
        ]

        reasons = []
        score = 0

        if failed >= 5:
            score += 35
            reasons.append(f"Repeated failed logins ({failed})")
        elif failed >= 3:
            score += 20
            reasons.append(f"Several failed logins ({failed})")
        elif failed:
            score += 5
            reasons.append(f"Failed login observed ({failed})")

        if len(usernames) >= 5:
            score += 25
            reasons.append(f"Many usernames attempted ({len(usernames)})")
        elif len(usernames) >= 3:
            score += 15
            reasons.append(f"Multiple usernames attempted ({len(usernames)})")

        matched = set()
        for command in commands:
            for label, pattern in SUSPICIOUS_PATTERNS.items():
                if re.search(pattern, command, re.IGNORECASE):
                    matched.add(label)

        if matched:
            score += min(10 * len(matched), 30)
            reasons.extend(f"Command pattern: {item}" for item in sorted(matched))

        if len(commands) >= 10:
            score += 10
            reasons.append(f"High command volume ({len(commands)})")

        score = min(score, 100)
        level = "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"

        results.append({
            "source_ip": ip,
            "risk_score": score,
            "risk_level": level,
            "failed_logins": failed,
            "successful_logins": successful,
            "unique_usernames": len(usernames),
            "commands_recorded": len(commands),
            "usernames": ", ".join(usernames),
            "commands": " | ".join(commands),
            "reasons": "; ".join(reasons) if reasons else "No configured high-risk rule matched",
        })

    df = pd.DataFrame(results).sort_values("risk_score", ascending=False)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    suffix = "_test" if len(sys.argv) > 1 else ""
    csv_file = REPORT_DIR / f"attack_analysis{suffix}.csv"
    txt_file = REPORT_DIR / f"attack_analysis{suffix}.txt"
    df.to_csv(csv_file, index=False)

    with txt_file.open("w", encoding="utf-8") as f:
        f.write("HONEYPOT ATTACK-BEHAVIOUR ANALYSIS\n")
        f.write("==================================\n")
        f.write(f"Events examined: {len(events)}\n")
        f.write(f"Source IPs examined: {len(by_ip)}\n")
        f.write("Scores are rule-based indicators, not proof of an attack.\n\n")

        for _, row in df.iterrows():
            f.write(f"Source: {row['source_ip']}\n")
            f.write(f"Risk: {row['risk_score']}/100 ({row['risk_level']})\n")
            f.write(f"Failed logins: {row['failed_logins']}\n")
            f.write(f"Usernames: {row['usernames'] or 'None recorded'}\n")
            f.write(f"Commands: {row['commands'] or 'None recorded'}\n")
            f.write(f"Reasons: {row['reasons']}\n\n")

    print("=== Attack Behaviour Analysis ===")
    print(f"Events examined: {len(events)}")
    print(f"Source IPs examined: {len(by_ip)}")
    for _, row in df.iterrows():
        print(f"\n{row['source_ip']} | {row['risk_score']}/100 | {row['risk_level']}")
        print(f"  Reasons: {row['reasons']}")
    print(f"\nCSV report: {csv_file}")
    print(f"Text report: {txt_file}")

if __name__ == "__main__":
    main()
