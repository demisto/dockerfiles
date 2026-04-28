"""Smoke test for the demisto/browser-use image.

Verifies that:
  * Every Python dependency declared in the Pipfile imports cleanly.
  * The system google-chrome binary is present (provided by the
    demisto/chromium base image) and reports a sane version.
  * Playwright can actually launch that Chrome in headless mode and load a
    page. This catches missing OS-level shared libraries that would otherwise
    only show up at runtime.

The script must exit with status 0 on success.
"""

import os
import subprocess
import sys

# 1. Ensure every library shipped in the image imports without error.
import anthropic  # noqa: F401
import google.generativeai  # noqa: F401
import openai  # noqa: F401
import pydantic  # noqa: F401
import browser_use  # noqa: F401
import playwright  # noqa: F401
from playwright.sync_api import sync_playwright

print(f"browser-use version: {browser_use.__version__}")
print(f"playwright version:  {playwright.__version__}")
print(f"anthropic version:   {anthropic.__version__}")
print(f"openai version:      {openai.__version__}")
print(f"pydantic version:    {pydantic.__version__}")

# 2. Confirm the system google-chrome binary (from the demisto/chromium base
#    image) is present and runs.
chrome_exe = os.environ.get(
    "PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH",
    "/opt/google/chrome/google-chrome",
)
chrome_version = subprocess.check_output([chrome_exe, "--version"], text=True).strip()
print(f"chrome binary:       {chrome_exe}")
print(f"chrome version:      {chrome_version}")

# 3. Make sure Playwright can drive that Chrome through its `chrome` channel
#    (so it does not try to use a Playwright-managed Chromium build, which we
#    deliberately did not download).
with sync_playwright() as p:
    browser = p.chromium.launch(
        channel="chrome",
        executable_path=chrome_exe,
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage"],
    )
    try:
        page = browser.new_page()
        page.goto("data:text/html,<title>ok</title><h1>hello</h1>")
        title = page.title()
        print(f"page title:          {title}")
        assert title == "ok", f"unexpected page title: {title!r}"
    finally:
        browser.close()

print("All is good!!!")
sys.exit(0)
