# security_agent/csrf_detector.py
from urllib.parse import urlparse
import secrets

ALLOWED_ORIGINS = {
    "http://127.0.0.1:8000",
    "http://localhost:8000",
}

def generate_csrf_token():
    return secrets.token_hex(32)

def check_csrf(features):
    method = (features.get("method") or "GET").upper()
    if method not in ("POST", "PUT", "DELETE", "PATCH"):
        return False, None

    origin = features.get("origin")
    referer = features.get("referer")
    session = features.get("session", {})

    session_token = session.get("csrf_token")
    headers = features.get("headers") or {}
    sent_token = headers.get("X-CSRF-Token") or headers.get("x-csrf-token")
    sent_token = sent_token or features.get("body_params", {}).get("csrf_token")

    if not session_token:
        return True, "no_session_csrf_token"

    if not sent_token:
        return True, "missing_csrf_token"

    if sent_token != session_token:
        return True, "invalid_csrf_token"

    if origin and origin not in ALLOWED_ORIGINS:
        return True, f"origin_not_allowed:{origin}"

    elif referer:
        try:
            from urllib.parse import urlparse
            ref_host = urlparse(referer).netloc
            allowed_hosts = {urlparse(o).netloc for o in ALLOWED_ORIGINS}
            if ref_host not in allowed_hosts:
                return True, f"referer_not_allowed:{ref_host}"
        except Exception:
            return True, "malformed_referer"

    return False, None


# ----------------------------
# 🟢 Ajouter la classe demandée
# ----------------------------
class CSRFDetector:
    def detect(self, features):
        flagged, reason = check_csrf(features)
        return {
            "malicious": flagged,
            "reason": reason
        }
