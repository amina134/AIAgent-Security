# security_agent/ssrf_detector.py
import socket
from urllib.parse import urlparse
import ipaddress

PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
]

FORBIDDEN_SCHEMES = {"file", "gopher", "ftp", "dict", "php", "jar"}


def _is_ip_private(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in PRIVATE_NETWORKS)
    except Exception:
        return False

def resolve_host_to_ips(hostname):
    try:
        infos = socket.getaddrinfo(hostname, None)
        return list({info[4][0] for info in infos})
    except Exception:
        return []

def detect_ssrf_from_url(url):
    if not url:
        return False, None

    try:
        parsed = urlparse(url)
    except Exception:
        return True, "malformed_url"

    scheme = (parsed.scheme or "").lower()
    if scheme in FORBIDDEN_SCHEMES:
        return True, f"forbidden_scheme:{scheme}"

    host = parsed.hostname
    if not host:
        return True, "no_hostname"

    try:
        ipaddress.ip_address(host)
        if _is_ip_private(host):
            return True, f"internal_ip:{host}"
    except Exception:
        ips = resolve_host_to_ips(host)
        if not ips:
            return True, "dns_resolution_failed"
        for ip in ips:
            if _is_ip_private(ip):
                return True, f"internal_ip:{ip}"

    return False, None


# ----------------------------
# 🟢 Classe demandée
# ----------------------------
class SSRFDetector:
    def detect(self, url: str):
        flagged, reason = detect_ssrf_from_url(url)
        return {
            "malicious": flagged,
            "reason": reason,
            "input": url
        }
