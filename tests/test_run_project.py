
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

def test_integrated_workflow_completes():
    result = subprocess.run(
        [sys.executable, "run_project.py"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )

    output = result.stdout + result.stderr

    assert result.returncode == 0, output
    assert "PROJECT WORKFLOW COMPLETED" in output

    reports = [
        "cowrie_events.csv",
        "analysis_summary.txt",
        "attack_analysis.csv",
        "attack_analysis.txt",
        "adaptive_response.json",
    ]

    for report in reports:
        assert (PROJECT_ROOT / "reports" / report).exists(), (
            f"Expected report was not generated: {report}"
        )
