"""SimuGuard AI Dashboard launcher from workspace root."""

import runpy
import sys
from pathlib import Path

PKG_DIR = (Path(__file__).parent / "simuguard-demo").resolve()
if str(PKG_DIR) not in sys.path:
    sys.path.insert(0, str(PKG_DIR))

inner_app = PKG_DIR / "app.py"

if __name__ == "__main__":
    runpy.run_path(str(inner_app), run_name="__main__")
