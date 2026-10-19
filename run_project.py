import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent

steps = [
    ("Cowrie Log Analysis", [sys.executable, "src/analyze_logs.py"]),
    ("Attack Behaviour Analysis", [
        sys.executable, "src/attack_analysis.py"
    ]),
    ("Adaptive Monitoring Response", [
        sys.executable, "src/adaptive_response.py"
    ]),
]

print("=" * 55)
print("ADAPTIVE HONEYPOT - INTEGRATED RUN")
print("=" * 55)

for name, command in steps:
    print(f"\n\n--- {name} ---")
    result = subprocess.run(command, cwd=BASE)

    if result.returncode != 0:
        print(f"\nStopped: {name} failed.")
        sys.exit(result.returncode)

print("\n" + "=" * 55)
print("PROJECT WORKFLOW COMPLETED")
print("Check the reports/ folder for generated results.")
print("=" * 55)
