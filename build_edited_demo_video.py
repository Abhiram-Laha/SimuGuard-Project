import os
import sys
import numpy as np
from PIL import Image, ImageDraw, ImageFont
import subprocess
import imageio_ffmpeg
import scipy.io.wavfile as wavfile

DEMO_DIR = os.path.abspath(os.path.join("prestation docs tuesday", "demo_video"))
RAW_DIR = os.path.join(DEMO_DIR, "raw")
TEMP_DIR = os.path.join(DEMO_DIR, "temp")
os.makedirs(TEMP_DIR, exist_ok=True)

FFMPEG_EXE = imageio_ffmpeg.get_ffmpeg_exe()
print(f"Using FFmpeg: {FFMPEG_EXE}")

FONT_TITLE = r"C:\Windows\Fonts\segoeuib.ttf"
FONT_REGULAR = r"C:\Windows\Fonts\segoeui.ttf"
FONT_BOLD = r"C:\Windows\Fonts\arialbd.ttf"

# =============================================================================
# 1. GENERATE OPENING TITLE CARD (1920x1080)
# =============================================================================
def create_title_card(output_path):
    img = Image.new("RGBA", (1920, 1080), (11, 19, 43, 255))
    draw = ImageDraw.Draw(img)

    # Subtle tech grid / border
    draw.rectangle([(60, 60), (1860, 1020)], outline=(30, 58, 138), width=2)
    draw.rectangle([(70, 70), (1850, 1010)], outline=(2, 132, 199), width=1)

    f_brand = ImageFont.truetype(FONT_TITLE, 28)
    f_main = ImageFont.truetype(FONT_TITLE, 64)
    f_sub = ImageFont.truetype(FONT_REGULAR, 32)
    f_meta_b = ImageFont.truetype(FONT_TITLE, 24)
    f_meta_r = ImageFont.truetype(FONT_REGULAR, 22)

    # Top Brand Tag
    draw.text((960, 180), "ENTERPRISE PRE-DEPLOYMENT SECURITY SIMULATION", font=f_brand, fill=(56, 189, 248), anchor="mm")
    
    # Main Title
    draw.text((960, 290), "SimuGuard AI — Working Demonstration", font=f_main, fill=(255, 255, 255), anchor="mm")
    
    # Subtitle
    draw.text((960, 370), "End-to-End Firewall & IAM Pre-Flight Risk Analysis Pipeline", font=f_sub, fill=(203, 213, 225), anchor="mm")

    # Divider bar
    draw.line([(660, 430), (1260, 430)], fill=(2, 132, 199), width=3)

    # Demonstration Scenario Card
    draw.rounded_rectangle([(360, 480), (1560, 740)], radius=16, fill=(21, 34, 56), outline=(56, 189, 248), width=2)
    
    draw.text((960, 530), "DEMONSTRATION SCENARIO: CHG-NET-2026-3105", font=f_meta_b, fill=(251, 191, 36), anchor="mm")
    draw.text((960, 580), "Request: Direct Internet SSH Access to Analytics DMZ Subnet", font=f_meta_r, fill=(255, 255, 255), anchor="mm")
    draw.text((960, 630), "Target: Palo Alto PA-5450 (fw-edge-01-primary)  |  Rule: RULE-PAN-015", font=f_meta_r, fill=(203, 213, 225), anchor="mm")
    draw.text((960, 680), "Environment: Apex Global Technologies Synthetic Enterprise Testbed", font=f_meta_r, fill=(148, 163, 184), anchor="mm")

    # Presenters Footer
    draw.text((960, 830), "PRESENTERS:", font=f_brand, fill=(56, 189, 248), anchor="mm")
    draw.text((960, 880), "Ameya Shree Kasa — Security Engineer I    |    Abhiram Laha — Managed Service Engineer I", font=f_meta_b, fill=(255, 255, 255), anchor="mm")
    draw.text((960, 940), "Tuesday Project Presentation  •  Strict 3-Minute Defense Allotment", font=f_meta_r, fill=(148, 163, 184), anchor="mm")

    img.save(output_path)
    print(f"Created Title Card: {output_path}")

# =============================================================================
# 2. GENERATE CLOSING TITLE CARD (1920x1080)
# =============================================================================
def create_closing_card(output_path):
    img = Image.new("RGBA", (1920, 1080), (11, 19, 43, 255))
    draw = ImageDraw.Draw(img)

    draw.rectangle([(60, 60), (1860, 1020)], outline=(30, 58, 138), width=2)
    draw.rectangle([(70, 70), (1850, 1010)], outline=(16, 185, 129), width=1)

    f_main = ImageFont.truetype(FONT_TITLE, 64)
    f_sub = ImageFont.truetype(FONT_TITLE, 34)
    f_body = ImageFont.truetype(FONT_REGULAR, 24)
    f_bold = ImageFont.truetype(FONT_TITLE, 26)

    draw.text((960, 180), "SimuGuard AI", font=f_main, fill=(255, 255, 255), anchor="mm")
    draw.text((960, 260), "Identify Security Risks Before Deployment", font=f_sub, fill=(56, 189, 248), anchor="mm")

    draw.line([(660, 310), (1260, 310)], fill=(16, 185, 129), width=3)

    # Key Takeaways Box
    draw.rounded_rectangle([(360, 360), (1560, 720)], radius=16, fill=(21, 34, 56), outline=(16, 185, 129), width=2)

    takeaways = [
        ("✔ Verified Simulation Verdict:", "WARN_MANUAL_REVIEW (Composite Risk Score: 51.0 / 100)"),
        ("✔ Excessive Inbound Detected:", "Public SSH on TCP/22 directly to DMZ subnet flagged as high-risk"),
        ("✔ Architectural Recommendation:", "Route vendor support via corporate bastion (10.254.0.100/32) in Mgmt-OOB"),
        ("✔ Digital Twin Engine:", "Simulated against 220 in-memory nodes & 77 directional relationships"),
        ("✔ Production Testing Baseline:", "Backed by 350 passing automated tests with zero failures"),
    ]

    start_y = 420
    for title, desc in takeaways:
        draw.text((420, start_y), title, font=f_bold, fill=(52, 211, 153))
        draw.text((820, start_y), desc, font=f_body, fill=(255, 255, 255))
        start_y += 55

    # Closing greeting
    draw.text((960, 800), "“Proactive Prevention Over Reactive Outage Firefighting”", font=f_sub, fill=(251, 191, 36), anchor="mm")
    draw.text((960, 870), "Ameya Shree Kasa — Security Engineer I    |    Abhiram Laha — Managed Service Engineer I", font=f_bold, fill=(255, 255, 255), anchor="mm")
    draw.text((960, 940), "Thank You — We Welcome Your Questions", font=f_main, fill=(56, 189, 248), anchor="mm")

    img.save(output_path)
    print(f"Created Closing Card: {output_path}")

# =============================================================================
# 3. GENERATE STEP CAPTION BANNERS
# =============================================================================
def create_caption_banner(step_num, title, detail, output_path):
    # Banner size 1760 x 110 placed at bottom
    banner = Image.new("RGBA", (1760, 110), (11, 19, 43, 230))
    draw = ImageDraw.Draw(banner)
    
    # Cyan border and rounded look
    draw.rectangle([(0, 0), (1759, 109)], outline=(2, 132, 199), width=2)
    draw.line([(0, 0), (8, 109)], fill=(56, 189, 248), width=6) # Accent left bar

    f_step = ImageFont.truetype(FONT_TITLE, 22)
    f_detail = ImageFont.truetype(FONT_REGULAR, 20)

    draw.text((30, 30), f"STEP {step_num}: {title.upper()}", font=f_step, fill=(56, 189, 248))
    draw.text((30, 68), detail, font=f_detail, fill=(255, 255, 255))

    banner.save(output_path)

# =============================================================================
# 4. GENERATE AMBIENT CYBER SOUNDTRACK (150s, 44.1kHz, Stereo)
# =============================================================================
def generate_ambient_soundtrack(output_wav_path, duration_sec=150):
    sr = 44100
    t = np.linspace(0, duration_sec, int(sr * duration_sec), endpoint=False)
    
    # Tech chord progression: C minor 7 (C3, Eb3, G3, Bb3) -> Ab maj7 -> Fm7 -> Gsus4
    # Frequencies: C3=130.81, Eb3=155.56, G3=196.00, Bb3=233.08, Ab2=103.83, C4=261.63
    chord_len = 15.0 # change chord every 15s
    
    audio_l = np.zeros_like(t)
    audio_r = np.zeros_like(t)
    
    chords = [
        [130.81, 155.56, 196.00, 261.63], # Cm
        [103.83, 130.81, 155.56, 207.65], # Ab
        [87.31, 130.81, 155.56, 174.61],  # Fm
        [98.00, 146.83, 196.00, 261.63],  # Gsus4
    ]
    
    for i, chord in enumerate(chords):
        # repeat cycle across duration
        for rep in range(int(duration_sec / (len(chords) * chord_len)) + 1):
            start_t = (rep * len(chords) + i) * chord_len
            end_t = start_t + chord_len
            mask = (t >= start_t) & (t < end_t)
            if not np.any(mask):
                continue
            t_sub = t[mask] - start_t
            env = np.sin(np.pi * (t_sub / chord_len)) ** 1.5 # smooth bell envelope
            
            wave_sub = np.zeros_like(t_sub)
            for f in chord:
                # Add fundamental + gentle harmonic
                wave_sub += np.sin(2 * np.pi * f * t_sub) * 0.4
                wave_sub += np.sin(2 * np.pi * (f * 2) * t_sub) * 0.15
                wave_sub += np.sin(2 * np.pi * (f * 1.5) * t_sub) * 0.08
            
            # Gentle stereo panning
            audio_l[mask] += wave_sub * env * 0.25 * (0.8 + 0.2 * np.sin(0.5 * t_sub))
            audio_r[mask] += wave_sub * env * 0.25 * (0.8 - 0.2 * np.sin(0.5 * t_sub))

    # Add gentle rhythmic high-frequency tech pulse (8 Hz)
    pulse = 0.04 * np.sin(2 * np.pi * 523.25 * t) * (0.5 + 0.5 * np.sin(2 * np.pi * 4 * t))**4
    audio_l += pulse
    audio_r += pulse

    # Master Fade In (3s) and Fade Out (4s)
    fade_in_len = int(sr * 3.5)
    fade_out_len = int(sr * 4.5)
    
    fade_in = np.linspace(0, 1, fade_in_len)
    fade_out = np.linspace(1, 0, fade_out_len)
    
    audio_l[:fade_in_len] *= fade_in
    audio_r[:fade_in_len] *= fade_in
    audio_l[-fade_out_len:] *= fade_out
    audio_r[-fade_out_len:] *= fade_out

    # Normalize to -16dB
    max_val = max(np.max(np.abs(audio_l)), np.max(np.abs(audio_r)))
    if max_val > 0:
        audio_l = (audio_l / max_val) * 0.35
        audio_r = (audio_r / max_val) * 0.35

    stereo = np.column_stack((audio_l, audio_r))
    int_audio = np.int16(stereo * 32767)
    wavfile.write(output_wav_path, sr, int_audio)
    print(f"Generated soundtrack: {output_wav_path}")

# =============================================================================
# 5. ASSEMBLE FULL VIDEO VIA FFMPEG
# =============================================================================
def compile_demo_video():
    raw_video = os.path.join(RAW_DIR, "SimuGuard_AI_Raw_Recording.webm")
    title_png = os.path.join(TEMP_DIR, "title_card.png")
    closing_png = os.path.join(TEMP_DIR, "closing_card.png")
    audio_wav = os.path.join(TEMP_DIR, "soundtrack.wav")
    
    create_title_card(title_png)
    create_closing_card(closing_png)
    
    # Generate 10 caption overlays
    captions = [
        (1, "Dashboard & Workspace Intake", "Single Assessment Workspace loaded in Apex Global Technologies Enterprise Demo Environment"),
        (2, "Submitting Change Ticket CHG-NET-2026-3105", "Vendor requested direct Internet SSH access (port 22) into Analytics DMZ workers"),
        (3, "Automated Configuration Extraction", "Extracting Target Firewall fw-edge-01-primary (Palo Alto PA-5450) and Rule RULE-PAN-015"),
        (4, "Configuration Warnings Detected", "Flagged Security Profile NONE (zero threat inspection) and 4 pending stakeholder sign-offs"),
        (5, "Executing Pre-Flight Simulation", "Cloning in-memory Digital Twin graph (220 nodes & 77 relationships) to evaluate ripple impact"),
        (6, "Simulation Verdict & Risk Scoring", "Verified Output: WARN_MANUAL_REVIEW with Composite Risk Score: 51.0 / 100 (Medium Risk)"),
        (7, "Affected Assets & Blast Radius Analysis", "Directly touches edge firewall, obj-dmz-analytics-subnet (10.100.4.0/24), and worker nodes"),
        (8, "Dataset Security Classification", "Synthetic enterprise dataset confirms RULE-PAN-015 is INTENTIONAL_MISCONFIG_EXCESSIVE_INBOUND"),
        (9, "Architectural Recommendation", "Recommended Path: Route support through corporate management bastion (10.254.0.100/32) in Mgmt-OOB"),
        (10, "Compliance & Audit Export", "Generating one-click executive audit PDF and machine-readable JSON compliance artifacts"),
    ]

    caption_pngs = []
    for s_num, s_title, s_desc in captions:
        c_path = os.path.join(TEMP_DIR, f"caption_step_{s_num}.png")
        create_caption_banner(s_num, s_title, s_desc, c_path)
        caption_pngs.append(c_path)

    # Calculate timestamps for ~150s video
    # Title: 0.0 -> 6.5s
    # Step 1: 6.5 -> 18.0s (11.5s)
    # Step 2: 18.0 -> 34.0s (16.0s)
    # Step 3: 34.0 -> 48.0s (14.0s)
    # Step 4: 48.0 -> 62.0s (14.0s)
    # Step 5: 62.0 -> 78.0s (16.0s)
    # Step 6: 78.0 -> 98.0s (20.0s)
    # Step 7: 98.0 -> 114.0s (16.0s)
    # Step 8: 114.0 -> 126.0s (12.0s)
    # Step 9: 126.0 -> 138.0s (12.0s)
    # Step 10: 138.0 -> 148.0s (10.0s)
    # Closing: 148.0 -> 158.0s (10.0s)
    # Total duration = 158 seconds (2 minutes 38 seconds)

    total_duration = 158.0
    generate_ambient_soundtrack(audio_wav, duration_sec=int(total_duration))

    mp4_target = os.path.join(DEMO_DIR, "SimuGuard_AI_Working_Demo.mp4")
    webm_target = os.path.join(DEMO_DIR, "SimuGuard_AI_Working_Demo.webm")

    print("Building composite video with FFmpeg...")

    # Build complex filter:
    # 0: title image looped for 6.5s
    # 1: raw video stretched/paced with setpts to cover 6.5s -> 148.0s (duration 141.5s; raw is 83.28s -> pts ratio = 141.5/83.28 = 1.7)
    # 2: closing image looped for 10.0s
    # 3..12: caption PNG overlays placed with enable='between(t, start, end)'
    # 13: audio track

    filter_complex = [
        # Source 0: Title (0 to 6.5s) with fade in/out
        "[0:v]loop=loop=162:size=1:start=0,scale=1920:1080,format=yuv420p,fade=t=in:st=0:d=1.0,fade=t=out:st=5.5:d=1.0[title];",
        
        # Source 1: App capture paced smoothly (duration ~141.5s)
        "[1:v]setpts=1.70*PTS,scale=1920:1080,format=yuv420p[app];",
        
        # Source 2: Closing (0 to 10s) with fade in/out
        "[2:v]loop=loop=250:size=1:start=0,scale=1920:1080,format=yuv420p,fade=t=in:st=0:d=1.0,fade=t=out:st=8.5:d=1.5[closing];",
        
        # Concatenate Title + App + Closing
        "[title][app][closing]concat=n=3:v=1:a=0[v_base];",
    ]

    # Overlay captions on v_base
    # x=80, y=930
    timing_windows = [
        (6.5, 18.0),   # 1
        (18.0, 34.0),  # 2
        (34.0, 48.0),  # 3
        (48.0, 62.0),  # 4
        (62.0, 78.0),  # 5
        (78.0, 98.0),  # 6
        (98.0, 114.0), # 7
        (114.0, 126.0),# 8
        (126.0, 138.0),# 9
        (138.0, 148.0),# 10
    ]

    curr_v = "v_base"
    for idx, (st_t, ed_t) in enumerate(timing_windows):
        input_idx = 3 + idx
        next_v = f"v_cap_{idx}"
        filter_complex.append(
            f"[{curr_v}][{input_idx}:v]overlay=80:930:enable='between(t,{st_t},{ed_t})':format=auto[{next_v}];"
        )
        curr_v = next_v

    # Final visual output
    filter_complex_str = "".join(filter_complex)
    # Remove trailing semicolon
    if filter_complex_str.endswith(";"):
        filter_complex_str = filter_complex_str[:-1]

    # Inputs list for ffmpeg
    cmd_mp4 = [
        FFMPEG_EXE, "-y",
        "-loop", "1", "-t", "6.5", "-i", title_png,          # 0
        "-i", raw_video,                                      # 1
        "-loop", "1", "-t", "10.0", "-i", closing_png,        # 2
    ]

    for c_png in caption_pngs:
        cmd_mp4.extend(["-i", c_png])                          # 3 .. 12

    cmd_mp4.extend(["-i", audio_wav])                          # 13 (Audio)

    cmd_mp4.extend([
        "-filter_complex", filter_complex_str,
        "-map", f"[{curr_v}]",
        "-map", "13:a",
        "-c:v", "libx264",
        "-preset", "medium",
        "-crf", "19",
        "-pix_fmt", "yuv420p",
        "-c:a", "aac",
        "-b:a", "192k",
        "-shortest",
        mp4_target
    ])

    print("Running FFmpeg MP4 encoding...")
    res = subprocess.run(cmd_mp4, capture_output=True, text=True)
    if res.returncode != 0:
        print("FFmpeg MP4 Error:", res.stderr)
        sys.exit(1)
    print(f"Successfully generated: {mp4_target}")

    # Convert to WebM using VP9
    print("Encoding WebM (VP9) version...")
    cmd_webm = [
        FFMPEG_EXE, "-y",
        "-i", mp4_target,
        "-c:v", "libvpx-vp9",
        "-b:v", "1500k",
        "-c:a", "libopus",
        "-b:a", "128k",
        webm_target
    ]
    res_webm = subprocess.run(cmd_webm, capture_output=True, text=True)
    if res_webm.returncode != 0:
        print("FFmpeg WebM warning/error:", res_webm.stderr[:400])
    else:
        print(f"Successfully generated: {webm_target}")

if __name__ == "__main__":
    compile_demo_video()
