"""Run both automated test suites and create the Testing screenshots from the real output.

    python tools/capture_tests.py

Raw logs are saved to Documentation/raw_test_logs/ and rendered to Screenshots/Testing/.
"""
import subprocess
import sys
from pathlib import Path

from render_text import render_text

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "Documentation" / "raw_test_logs"
OUT = ROOT / "Screenshots" / "Testing"

SUITES = [
    ("Section_B_RBAC", "01_rbac_pytest_results.png", "pytest  -  Section B RBAC"),
    ("Section_D_Cryptography", "02_crypto_pytest_results.png", "pytest  -  Section D cryptography"),
]


def main():
    RAW.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    all_passed = True
    for folder, png, title in SUITES:
        result = subprocess.run([sys.executable, "-m", "pytest", "-v", "--tb=short"],
                                cwd=ROOT / folder, capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=600)
        text = result.stdout + result.stderr
        (RAW / f"{folder}_pytest.txt").write_text(text, encoding="utf-8")
        summary = [line for line in text.splitlines() if " passed" in line or " failed" in line][-1:]
        print(f"{folder}: exit {result.returncode} | {summary[0] if summary else 'no summary line'}")
        if result.returncode != 0:
            all_passed = False
        # Keep the verbose results and the final summary line in the screenshot
        keep = [line for line in text.splitlines()
                if "PASSED" in line or "FAILED" in line or "ERROR" in line or " passed" in line or " failed" in line]
        render_text("\n".join(keep), OUT / png, title)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
