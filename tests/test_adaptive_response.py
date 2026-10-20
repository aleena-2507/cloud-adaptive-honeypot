import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest

from src.adaptive_response import choose_response


@pytest.mark.parametrize(
    "score, expected",
    [
        (0, ("NORMAL", "CONTINUE_MONITORING")),
        (29, ("NORMAL", "CONTINUE_MONITORING")),
        (30, ("ENHANCED", "ENHANCED_REVIEW")),
        (59, ("ENHANCED", "ENHANCED_REVIEW")),
        (60, ("INTENSIVE", "PRIORITY_ALERT")),
        (100, ("INTENSIVE", "PRIORITY_ALERT")),
    ],
)
def test_choose_response(score, expected):
    assert choose_response(score) == expected
def test_high_risk_csv_triggers_priority_alert(tmp_path):
    project_dir = Path(__file__).resolve().parents[1]
    script = project_dir / "src" / "adaptive_response.py"
    output_file = project_dir / "reports" / "adaptive_response_test.json"
    input_file = tmp_path / "high_risk.csv"

    input_file.write_text(
        "source_ip,risk_score,risk_level\n"
        "192.0.2.10,80,HIGH\n",
        encoding="utf-8"
    )

    result = subprocess.run(
        [sys.executable, str(script), str(input_file)],
        capture_output=True,
        text=True,
        timeout=30
    )

    assert result.returncode == 0, result.stderr
    assert "80/100 | INTENSIVE | PRIORITY_ALERT" in result.stdout

    decisions = json.loads(output_file.read_text(encoding="utf-8"))
    assert decisions[0]["risk_score"] == 80
    assert decisions[0]["monitoring_level"] == "INTENSIVE"
    assert decisions[0]["action"] == "PRIORITY_ALERT"

    output_file.unlink()
