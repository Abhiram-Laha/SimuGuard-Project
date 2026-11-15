"""Validation script for Apex_Global_Technologies_Complete_Enterprise_Architecture.pptx."""

from pathlib import Path
from pptx import Presentation

pptx_path = Path("simuguard-demo/deliverables/Apex_Global_Technologies_Complete_Enterprise_Architecture.pptx")
assert pptx_path.is_file(), f"PPTX file missing: {pptx_path}"
print(f"File exists: {pptx_path}")
print(f"File size: {pptx_path.stat().st_size:,} bytes")

prs = Presentation(str(pptx_path))
print(f"Total slides: {len(prs.slides)}")
assert len(prs.slides) == 20, f"Expected 20 slides, got {len(prs.slides)}"

print("\n--- Slide Titles & Content Inspection ---")
for idx, slide in enumerate(prs.slides, start=1):
    shape_count = len(slide.shapes)
    texts = []
    has_table = False
    for shape in slide.shapes:
        if shape.has_text_frame:
            for p in shape.text_frame.paragraphs:
                txt = p.text.strip()
                if txt and len(txt) > 2:
                    texts.append(txt[:45])
        elif shape.has_table:
            has_table = True
            rows = len(shape.table.rows)
            cols = len(shape.table.columns)
            texts.append(f"[Table: {rows}x{cols}]")
    
    first_title = texts[0] if texts else "No Text"
    second_title = texts[1] if len(texts) > 1 else ""
    print(f"Slide {idx:02d}: shapes={shape_count:2d}, table={str(has_table):5s}, sample='{first_title} | {second_title}'")

print("\nAll 20 slides validated successfully!")
