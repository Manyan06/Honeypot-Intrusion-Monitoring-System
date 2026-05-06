# geoip_lookup.py
import requests

_cache = {}

PRIVATE_PREFIXES = ("192.168.", "10.", "172.16.", "172.17.", "127.", "::1", "0.0.0.0")

def lookup_ip(ip):
    if not ip or ip == "unknown":
        return _default("Unknown")

    if ip in _cache:
        return _cache[ip]

    if any(ip.startswith(p) for p in PRIVATE_PREFIXES):
        result = {
            "country": "Local Network", "countryCode": "LO",
            "city": "Internal Lab",    "isp": "Private Network",
            "lat": 20.5937, "lon": 78.9629, "status": "local"
        }
        _cache[ip] = result
        return result

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        _cache[ip] = data
        return data
    except Exception:
        fallback = _default("Unknown")
        _cache[ip] = fallback
        return fallback

def _default(label):
    return {
        "country": label, "countryCode": "??",
        "city": label,    "isp": label,
        "lat": 0, "lon": 0, "status": "error"
    }