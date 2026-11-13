"""Render captured console/test output as a PNG image.

Used because the build environment has no graphical terminal. The text is the REAL captured output
of a command run (see capture_crypto.py and capture_tests.py); only its appearance is styled.
On Windows you can also take a native screenshot of PowerShell (see Screenshots/README.md).
"""
import html
import re

from playwright.sync_api import sync_playwright

PAGE = """<!doctype html><html><head><meta charset="utf-8"><style>
  body {{ margin: 0; padding: 18px; background: #eef1f6; }}
  .win {{ display: inline-block; min-width: 880px; background: #0c0c0c; border-radius: 10px;
          overflow: hidden; box-shadow: 0 6px 22px rgba(0,0,0,.35); }}
  .bar {{ background: #2b2f38; color: #d7dae0; font: 600 13px 'Segoe UI', Arial, sans-serif;
          padding: 8px 14px; }}
  pre {{ margin: 0; padding: 14px 18px; color: #e6e6e6; font: 13px/1.38 Consolas, 'Cascadia Mono',
         'DejaVu Sans Mono', monospace; white-space: pre-wrap; word-break: break-word; }}
  .hdr {{ color: #e5c07b; font-weight: 700; }}
  .ok {{ color: #7ec699; }}
  .bad {{ color: #ef8a80; }}
  .warn {{ color: #f0c674; }}
  .dim {{ color: #8b949e; }}
</style></head><body><div class="win"><div class="bar">{title}</div><pre>{body}</pre></div></body></html>"""


def _colorize(line):
    escaped = html.escape(line)
    if line.startswith("== ["):
        return f'<span class="hdr">{escaped}</span>'
    if re.search(r"FAILED|ERROR|DECRYPTED \(unexpected\)|connected \(unexpected\)", line):
        return f'<span class="bad">{escaped}</span>'
    if re.search(r"REJECTED|-> False|Traceback", line):
        return f'<span class="warn">{escaped}</span>'
    if re.search(r"PASSED|passed|-> True|ACCEPTED|= True|: True|\b200\b|COMPLETED", line):
        return f'<span class="ok">{escaped}</span>'
    if line.startswith("127.0.0.1 - -"):
        return f'<span class="dim">{escaped}</span>'
    return escaped


def render_text(text, out_path, title):
    """Write `text` (captured output) to out_path as a PNG at 2x scale."""
    body = "\n".join(_colorize(line) for line in text.rstrip("\n").splitlines())
    page_html = PAGE.format(title=html.escape(title), body=body)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1000, "height": 400}, device_scale_factor=2)
        page.set_content(page_html)
        page.locator(".win").screenshot(path=str(out_path))
        browser.close()
