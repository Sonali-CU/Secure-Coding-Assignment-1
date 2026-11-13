"""Run the Section D demo and create the Cryptography screenshots from its real output.

    python tools/capture_crypto.py

* Runs Section_D_Cryptography/main.py and saves the complete output.
* Splits the output at its "== [Sxx] title ==" headers and renders each section as a PNG.
* Starts https_server.py and takes a real browser screenshot of the HTTPS page (Chromium).
"""
import socket
import subprocess
import sys
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

from render_text import render_text

ROOT = Path(__file__).resolve().parents[1]
CRYPTO = ROOT / "Section_D_Cryptography"
OUT = ROOT / "Screenshots" / "Cryptography"

FILES = {
    "K7": "09_key_management_metadata.png",
    "S10": "10_argon2_hash_generation.png",
    "S11": "11_password_verification_correct.png",
    "S12": "12_password_verification_incorrect.png",
    "S13": "13_aes_gcm_encryption.png",
    "S14": "14_aes_gcm_decryption.png",
    "S15": "15_hmac_generation.png",
    "S16": "16_hmac_verification.png",
    "S17": "17_tampered_message_rejection.png",
    "S18": "18_https_server_running_terminal.png",
}


def wait_for_port(port, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([sys.executable, "main.py"], cwd=CRYPTO, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=300)
    output = result.stdout + (("\n[stderr]\n" + result.stderr) if result.stderr.strip() else "")
    (OUT / "full_run_output.txt").write_text(output, encoding="utf-8")
    if result.returncode != 0 or "ALL DEMONSTRATIONS COMPLETED" not in result.stdout:
        print("main.py FAILED - no screenshots created")
        print(output[-3000:])
        return 1

    # Split into sections at "== [TAG] title ==" headers
    sections, current = [], None
    for line in result.stdout.splitlines():
        if line.startswith("== [") and line.endswith("=="):
            tag = line[4:line.index("]")]
            current = {"tag": tag, "title": line, "lines": [line]}
            sections.append(current)
        elif current is not None:
            current["lines"].append(line)

    made = []
    for section in sections:
        if section["tag"] not in FILES:
            continue
        name = FILES[section["tag"]]
        body = "\n".join(section["lines"]).strip("\n")
        render_text(body, OUT / name, f"main.py  -  {section['title'].strip('= []').split('] ', 1)[-1]}")
        made.append(name)

    # Real browser screenshot of the HTTPS server
    server = subprocess.Popen([sys.executable, "https_server.py"], cwd=CRYPTO,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        if not wait_for_port(8443):
            print("HTTPS server did not start")
            return 1
        with sync_playwright() as p:
            browser = p.chromium.launch()
            context = browser.new_context(ignore_https_errors=True,   # self-signed certificate
                                          viewport={"width": 900, "height": 420}, device_scale_factor=2)
            page = context.new_page()
            response = page.goto("https://127.0.0.1:8443/", wait_until="load")
            page.locator("body").screenshot(path=str(OUT / "18b_https_server_running_browser.png"))
            print("browser GET https://127.0.0.1:8443/ ->", response.status,
                  "| security details:", response.security_details() is not None)
            browser.close()
        made.append("18b_https_server_running_browser.png")
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()

    print("Created:", *made, sep="\n  ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
