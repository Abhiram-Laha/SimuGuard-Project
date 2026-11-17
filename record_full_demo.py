import os
import sys
import time
import subprocess
import urllib.request
from playwright.sync_api import sync_playwright

RAW_DIR = os.path.abspath(os.path.join("prestation docs tuesday", "demo_video", "raw"))
os.makedirs(RAW_DIR, exist_ok=True)

CHG_FILE = os.path.abspath(os.path.join(
    "SimuGuard_Realistic_Org_Change_Requests",
    "SimuGuard_Firewall_Sample_Change_Requests",
    "05_FW_Public_SSH_Inbound_Exposure.txt"
))

with open(CHG_FILE, "r", encoding="utf-8") as f:
    chg_text = f.read()

print("Loaded change request text length:", len(chg_text))

# Start Streamlit Server
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
        time.sleep(0.5)

if not healthy:
    print("Failed to start Streamlit server.")
    server_proc.terminate()
    sys.exit(1)

raw_video_target = os.path.join(RAW_DIR, "SimuGuard_AI_Raw_Recording.webm")

print("Launching Playwright Chromium at 1920x1080...")
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    context = browser.new_context(
        record_video_dir=RAW_DIR,
        record_video_size={"width": 1920, "height": 1080},
        viewport={"width": 1920, "height": 1080}
    )
    page = context.new_page()

    print("Step 1: Navigating to Streamlit application...")
    page.goto("http://127.0.0.1:8501", wait_until="networkidle")
    
    # Wait until Streamlit header renders
    page.wait_for_selector('h1, h2, [data-testid="stHeader"]', timeout=15000)
    time.sleep(6) # Show dashboard header & sidebar overview

    # Smooth mouse hover on sidebar
    page.mouse.move(120, 200)
    time.sleep(1.5)
    page.mouse.move(120, 320)
    time.sleep(1.5)
    page.mouse.move(120, 420)
    time.sleep(2)

    # Step 2: Scroll down to Change Request Input Area
    print("Step 2: Scrolling to Change Request intake...")
    page.evaluate("window.scrollBy({top: 450, behavior: 'smooth'});")
    time.sleep(4)

    textarea = page.locator('textarea[aria-label="ServiceNow Change Request Input"]')
    if not textarea.count():
        textarea = page.locator('textarea').first

    print("Step 3: Pasting CHG-NET-2026-3105 into intake form...")
    textarea.scroll_into_view_if_needed()
    time.sleep(1)
    box = textarea.bounding_box()
    if box:
        page.mouse.move(box["x"] + 100, box["y"] + 40)
        time.sleep(1)
        page.mouse.down()
        page.mouse.up()
    
    textarea.fill(chg_text)
    time.sleep(5) # Let viewer read the pasted ticket parameters

    # Step 4: Click Extract Configuration
    print("Step 4: Clicking 'Extract Configuration' button...")
    extract_btn = page.locator('button:has-text("Extract Configuration")')
    extract_btn.scroll_into_view_if_needed()
    time.sleep(1.5)
    
    ebox = extract_btn.bounding_box()
    if ebox:
        page.mouse.move(ebox["x"] + ebox["width"]/2, ebox["y"] + ebox["height"]/2)
        time.sleep(1)
        page.mouse.down()
        page.mouse.up()
    else:
        extract_btn.click()

    # Wait for extraction to complete and DOM to update
    time.sleep(5)

    # Step 5: Review Extracted Configuration & Warnings
    print("Step 5: Reviewing Extracted Configuration...")
    page.evaluate("window.scrollBy({top: 480, behavior: 'smooth'});")
    time.sleep(7) # Show Network Security domain, rule name, source, destination, and warning badges

    # Move mouse over warnings
    page.mouse.move(600, 480)
    time.sleep(2)
    page.mouse.move(600, 580)
    time.sleep(2)

    # Step 6: Scroll to Pre-Flight Assessment button
    print("Step 6: Scrolling to 'Run Pre-Flight Assessment' button...")
    page.evaluate("window.scrollBy({top: 420, behavior: 'smooth'});")
    time.sleep(3)

    run_btn = page.locator('button:has-text("Run Pre-Flight Assessment")')
    run_btn.scroll_into_view_if_needed()
    time.sleep(2)

    rbox = run_btn.bounding_box()
    if rbox:
        page.mouse.move(rbox["x"] + rbox["width"]/2, rbox["y"] + rbox["height"]/2)
        time.sleep(1.5)
        page.mouse.down()
        page.mouse.up()
    else:
        run_btn.click()

    # Wait for assessment simulation to complete
    time.sleep(6)

    # Step 7: Review Assessment Verdict & Composite Risk Score
    print("Step 7: Showing Verdict (WARN_MANUAL_REVIEW) and Risk Score (51.0/100)...")
    page.evaluate("window.scrollBy({top: 520, behavior: 'smooth'});")
    time.sleep(8) # Long pause on the main verdict and 51.0 score

    # Step 8: Review Directly Affected Infrastructure Assets & Blast Radius
    print("Step 8: Reviewing Affected Assets & Blast Radius...")
    page.evaluate("window.scrollBy({top: 480, behavior: 'smooth'});")
    time.sleep(8) # Show affected firewall, DMZ subnet, and host assets

    # Step 9: Review Security Findings & Rule Violations
    print("Step 9: Reviewing Security Findings & Misconfiguration Flags...")
    page.evaluate("window.scrollBy({top: 480, behavior: 'smooth'});")
    time.sleep(7) # Show RULE-PAN-015 excessive inbound warning

    # Step 10: Review Report Export Functionality
    print("Step 10: Reviewing Report Export options (PDF & JSON)...")
    page.evaluate("window.scrollBy({top: 450, behavior: 'smooth'});")
    time.sleep(6) # Show export buttons

    # Step 11: Smooth scroll back to summary overview
    print("Step 11: Scrolling back to top for final summary...")
    page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'});")
    time.sleep(6)

    video_obj = page.video
    context.close()
    browser.close()

    raw_path = video_obj.path()
    print(f"Captured raw video at: {raw_path}")

# Rename / copy raw video to definitive path
if os.path.exists(raw_path):
    if os.path.exists(raw_video_target):
        os.remove(raw_video_target)
    os.rename(raw_path, raw_video_target)
    print(f"Saved definitive raw recording to: {raw_video_target}")

server_proc.terminate()
server_proc.wait(timeout=5)
print("Recording workflow completed successfully!")
