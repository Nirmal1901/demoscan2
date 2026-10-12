from urllib.parse import urlsplit

import requests
from flask import Blueprint, jsonify, request

from .auth import require_auth

bp = Blueprint("webhooks", __name__)

ALLOWED_HOST = "hooks.vaultdesk.example"


@bp.post("/api/webhooks/test")
@require_auth
def test_webhook():
    url = (request.get_json() or {}).get("url", "")
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        return jsonify(error="host not allowed"), 400
    if (
        parts.scheme != "https"
        or parts.hostname != ALLOWED_HOST
        or parts.username
        or parts.password
        or port not in (None, 443)
    ):
        return jsonify(error="host not allowed"), 400
    resp = requests.post(url, json={"event": "ping"}, timeout=3, allow_redirects=False)
    return jsonify(status=resp.status_code)
