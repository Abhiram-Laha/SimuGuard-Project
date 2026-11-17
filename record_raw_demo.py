import os
import sys
import time
import subprocess
import urllib.request
from playwright.sync_api import sync_playwright

RAW_DIR = os.path.abspath(os.path.join("prestation docs tuesday", "demo_video", "raw"))
os.makedirs(RAW_DIR, exist_ok=True)

# Load CHG-NET-2026-3105 text
CHG_FILE = os.path.abspath(os.path.join(
    "SimuGuard_Realistic_Org_Change_Requests",
    "SimuGuard_Firewall_Sample_Change_Requests",
    "05_FW_Public_SSH_Inbound_Exposure.txt"
))

with open(CHG_FILE, "r", encoding="utf-8") as f:
    chg_text = f.read()

print("Loaded change request text length:", len(chg_text))

# 1. Start Streamlit Server
print("Starting Streamlit server on 127.0.0.1:8501...")
env = os.environ.copy()
env["PYTHONPATH"] = os.path.abspath("simuguard-demo")

server_proc = subprocess.Popen(
    [sys.executable, "-m", "streamlit", "run", "app.py",
     "--server.port", "8501",
     "--server.address", "127.0.0.1",
     "--server.headless", "true",
     "--browser.gatherUsageStats", "false",
     "--theme.base", "light"],
    cwd=os.path.abspath("."),
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

# Poll until server responds
healthy = False
for i in range(25):
    time.sleep(1)
    try:
        resp = urllib.request.urlopen("http://127.0.0.1:8501/_stcore/health", timeout=1)
        if resp.status == 200:
            healthy = True
            print(f"Streamlit healthy after {i+1} seconds!")
            break
    except Exception as e:
        print(f"Waiting for server... ({e})")

if not healthy:
    print("Failed to start Streamlit server. Terminating...")
    server_proc.terminate()
    sys.exit(1)

# 2. Record with Playwright
print("Launching Playwright Chromium at 1920x1080...")
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(
        record_video_dir=RAW_DIR,
        record_video_size={"width": 1920, "height": 1080},
        viewport={"width": 1920, "height": 1080}
    )
    page = context.new_page()

    print("Navigating to http://127.0.0.1:8501 ...")
    page.goto("http://127.0.0.1:8501", wait_until="networkidle")
    time.sleep(3)

    # 1. Landing View / Workspace overview
    print("Showing landing view & header...")
    time.sleep(4)

    # Scroll down to input area
    print("Scrolling to Change Request input area...")
    page.evaluate("window.scrollBy({top: 450, behavior: 'smooth'});")
    time.sleep(3)

    # Locate the text area
    textarea = page.locator('textarea[aria-label="ServiceNow Change Request Input"]')
    if not textarea.count():
        textarea = page.locator('textarea').first

    print("Clicking text area and entering CHG-NET-2026-3105...")
    textarea.click()
    time.sleep(1)
    textarea.fill(chg_text)
    time.sleep(3)

    # Click Extract Configuration
    print("Clicking 'Extract Configuration' button...")
    extract_btn = page.locator('button:has-text("Extract Configuration")')
    extract_btn.scroll_into_view_if_needed()
    time.sleep(1)
    extract_btn.click()
    time.sleep(4)

    # Scroll to view extracted configuration and warnings
    print("Viewing extracted configuration...")
    page.evaluate("window.scrollBy({top: 500, behavior: 'smooth'});")
    time.sleep(5)

    # Scroll to Pre-Flight Assessment button
    print("Scrolling to 'Run Pre-Flight Assessment' button...")
    run_btn = page.locator('button:has-text("Run Pre-Flight Assessment")')
    run_btn.scroll_into_view_if_needed()
    time.sleep(2)

    print("Clicking 'Run Pre-Flight Assessment' button...")
    run_btn.click()
    time.sleep(5)

    # Scroll through results
    print("Reviewing assessment results (Verdict, Risk Score, Findings)...")
    # Section 1: Verdict & Risk Score
    page.evaluate("window.scrollBy({top: 550, behavior: 'smooth'});")
    time.sleep(5)

    # Section 2: Affected Assets & Blast Radius
    print("Reviewing Affected Infrastructure Assets...")
    page.evaluate("window.scrollBy({top: 500, behavior: 'smooth'});")
    time.sleep(5)

    # Section 3: Security Findings & Rules
    print("Reviewing Security Findings & Policy Warnings...")
    page.evaluate("window.scrollBy({top: 500, behavior: 'smooth'});")
    time.sleep(5)

    # Section 4: Export Buttons & Final Report
    print("Viewing Report Export functionality...")
    page.evaluate("window.scrollBy({top: 500, behavior: 'smooth'});")
    time.sleep(5)

    # Scroll back to top smoothly
    print("Scrolling back to top of assessment...")
    page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'});")
    time.sleep(4)

    # Close context to save video
    print("Finalizing video recording...")
    video_path = page.video.path()
    context.close()
    browser.close()

print(f"Raw recording saved at: {video_path}")

# Terminate server
print("Terminating Streamlit server...")
server_proc.terminate()
server_proc.wait(timeout=5)
print("Done!")
