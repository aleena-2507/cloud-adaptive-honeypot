import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

BASE = Path(__file__).resolve().parents[1]
INPUT_FILE = BASE / "reports" / "attack_analysis.csv"
REPORT_DIR = BASE / "reports"

def choose_response(score):
    if score >= 60:
        return "INTENSIVE", "PRIORITY_ALERT"
    elif score >= 30:
        return "ENHANCED", "ENHANCED_REVIEW"
    return "NORMAL", "CONTINUE_MONITORING"

def main():
    input_file = (
        Path(sys.argv[1]).expanduser()
        if len(sys.argv) > 1
        else INPUT_FILE
    )

    if not input_file.exists():
        raise SystemExit(f"Missing input report: {input_file}")

    df = pd.read_csv(input_file)
    decisions = []

    for _, row in df.iterrows():
        score = int(row["risk_score"])
        level, action = choose_response(score)

        decisions.append({
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "source_ip": str(row["source_ip"]),
            "risk_score": score,
            "risk_level": str(row["risk_level"]),
            "monitoring_level": level,
            "action": action,
            "mode": "SIMULATED_POLICY_ONLY"
        })

    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    output_name = (
        "adaptive_response_test.json"
        if len(sys.argv) > 1
        else "adaptive_response.json"
    )

    output = REPORT_DIR / output_name
    output.write_text(json.dumps(decisions, indent=2), encoding="utf-8")

    print("=== Adaptive Monitoring Policy ===")
    for item in decisions:
        print(
            f"{item['source_ip']} | {item['risk_score']}/100 | "
            f"{item['monitoring_level']} | {item['action']}"
        )

    print(f"Policy report saved to: {output}")
    print("Note: This recommends monitoring actions; it does not block traffic.")

if __name__ == "__main__":
    main()
