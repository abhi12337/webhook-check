"""Generate a deliberately insecure demo project to try webhook-check on.

    python examples/make_demo.py demo-webhooks
    webhook-check scan demo-webhooks

The demo contains a Next.js + Express + Hono app (web/) and a FastAPI + Flask + Django
backend (api/) with common webhook mistakes, copied from tests/fixtures, plus a settings
file with a hard-coded signing secret. The fake secret is assembled at runtime so this
repository never contains a secret-shaped string. Nothing in it works anywhere.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURES = HERE.parent / "tests" / "fixtures"

FAKE_WHSEC = "whsec" + "_" + "DEMOdemoDEMOdemo0123456789notReal"

SETTINGS = f'''"""Django settings (excerpt)."""
import os

DEBUG = False
ALLOWED_HOSTS = ["api.example.com"]
STRIPE_SECRET_KEY = os.environ["STRIPE_SECRET_KEY"]
STRIPE_WEBHOOK_SECRET = "{FAKE_WHSEC}"
'''


def main(dest: str) -> None:
    root = Path(dest)
    if root.exists():
        shutil.rmtree(root)
    shutil.copytree(FIXTURES / "node_vulnerable", root / "web")
    shutil.copytree(FIXTURES / "py_vulnerable", root / "api")
    (root / "api" / "settings.py").write_text(SETTINGS, encoding="utf-8")
    print(f"Demo project written to {root}. Now run:  webhook-check scan {root}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo-webhooks")
