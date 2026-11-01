"""Development server: python -m portal (from dg-soc/demo-app).

Werkzeug's request log would write raw URLs, so it is silenced here. Use gunicorn
(README.md) for anything other than local development.
"""
import logging
import os

from .app import create_app

logging.getLogger("werkzeug").setLevel(logging.ERROR)
create_app().run(host=os.environ.get("PORTAL_HOST", "127.0.0.1"), port=int(os.environ.get("PORTAL_PORT", "8090")))
