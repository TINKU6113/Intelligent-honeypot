"""
probes.py
---------
Active threat-intelligence probes for attacker IPs.
Covers: whois/RDAP, reverse DNS, GeoIP, ping, traceroute, nmap, banner grab.
"""

import re
import socket
import shutil
import subprocess
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

try:
    import requests
except ImportError:
    requests = None  # type: ignore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _run_cmd(cmd: Iterable[str], timeout: int = 20) -> Dict[str, Any]:
    try:
        p = subprocess.run(
            list(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return {"rc": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "stdout": "", "stderr": "timeout"}
    except FileNotFoundError:
        return {"rc": -2, "stdout": "", "stderr": "command not found"}


def is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Individual probes
# ---------------------------------------------------------------------------

def probe_whois(target: str) -> Dict[str, Any]:
    """Run whois or fall back to RDAP if whois binary is absent."""
    if shutil.which("whois"):
        return _run_cmd(["whois", target], timeout=12)
    if requests:
        try:
            r = requests.get(f"https://rdap.org/ip/{target}", timeout=8)
            return {"rc": r.status_code, "stdout": r.text[:20_000], "stderr": ""}
        except Exception as e:
            return {"rc": -1, "stdout": "", "stderr": str(e)}
    return {"rc": -2, "stdout": "", "stderr": "whois not installed and requests unavailable"}


def probe_reverse_dns(ip: str) -> Dict[str, Any]:
    """Resolve IP to hostname via PTR record."""
    try:
        name, aliases, addrs = socket.gethostbyaddr(ip)
        return {"hostname": name, "aliases": aliases, "addrs": addrs}
    except Exception as e:
        return {"error": str(e)}


def probe_dns_records(name: str) -> Dict[str, Any]:
    """Fetch A/AAAA/MX/TXT/CNAME records using dig or socket fallback."""
    out: Dict[str, Any] = {}
    if shutil.which("dig"):
        for rtype in ("A", "AAAA", "MX", "TXT", "CNAME"):
            out[rtype] = _run_cmd(["dig", "+short", rtype, name], timeout=6).get("stdout", "")
        return out
    try:
        infos = socket.getaddrinfo(name, None)
        out["addrs"] = sorted({i[4][0] for i in infos})
    except Exception as e:
        out["error"] = str(e)
    return out


def probe_ping(target: str, count: int = 3) -> Dict[str, Any]:
    """Ping target and return stdout/rc."""
    if shutil.which("ping"):
        flag = "-n" if subprocess.os.name == "nt" else "-c"
        return _run_cmd(["ping", flag, str(count), target], timeout=12)
    return {"rc": -2, "stderr": "ping not found"}


def probe_traceroute(target: str) -> Dict[str, Any]:
    """Run traceroute/tracepath/tracert, whichever is available."""
    for tool in ("traceroute", "tracepath", "tracert"):
        if shutil.which(tool):
            return _run_cmd([tool, target], timeout=30)
    return {"rc": -2, "stderr": "no traceroute tool found"}


def probe_nmap(target: str, top_ports: int = 200) -> Dict[str, Any]:
    """Run a safe nmap version scan against the top N ports."""
    if not shutil.which("nmap"):
        return {"rc": -2, "stderr": "nmap not installed"}
    return _run_cmd(
        ["nmap", "-Pn", "-sV", "--top-ports", str(top_ports), target],
        timeout=150,
    )


def probe_banner(target: str, port: int, timeout: int = 6) -> Dict[str, Any]:
    """Grab banner from a TCP port; sends HTTP HEAD for ports 80/8080."""
    try:
        with socket.create_connection((target, port), timeout=timeout) as s:
            s.settimeout(timeout)
            if port in (80, 8080):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(4096)
            return {"port": port, "banner": data.decode(errors="replace")}
    except Exception as e:
        return {"port": port, "connect_error": str(e)}


def probe_geoip(target: str) -> Dict[str, Any]:
    """Query ipinfo.io and ip-api.com for geolocation data."""
    if not requests:
        return {"error": "requests not installed — run: pip install requests"}
    result: Dict[str, Any] = {}
    try:
        r = requests.get(f"https://ipinfo.io/{target}/json", timeout=6)
        if r.ok:
            result["ipinfo"] = r.json()
    except Exception as e:
        result["ipinfo_error"] = str(e)
    try:
        r2 = requests.get(f"http://ip-api.com/json/{target}", timeout=6)
        if r2.ok:
            result["ipapi"] = r2.json()
    except Exception as e:
        result["ipapi_error"] = str(e)
    return result


# ---------------------------------------------------------------------------
# Full probe orchestrator
# ---------------------------------------------------------------------------

def run_full_probes(
    ip: str,
    ports_to_probe: tuple = (22, 80, 443),
    ping_count: int = 3,
) -> Dict[str, Any]:
    """
    Run all available probes against an IP and return a structured summary dict.
    """
    print(f"\n[*] Running full probes for {ip} …")
    summary: Dict[str, Any] = {
        "ip": ip,
        "collected_at": _now_iso(),
        "probes": {},
    }

    print("  -> whois/rdap")
    summary["probes"]["whois"] = probe_whois(ip)

    print("  -> reverse DNS")
    summary["probes"]["reverse_dns"] = probe_reverse_dns(ip)

    print("  -> geoip")
    summary["probes"]["geoip"] = probe_geoip(ip)

    print(f"  -> ping (count={ping_count})")
    summary["probes"]["ping"] = probe_ping(ip, count=ping_count)

    print("  -> traceroute")
    summary["probes"]["traceroute"] = probe_traceroute(ip)

    print(f"  -> banner grabs: {ports_to_probe}")
    summary["probes"]["banners"] = {}
    for port in ports_to_probe:
        summary["probes"]["banners"][str(port)] = probe_banner(ip, port)

    print("[*] Probes complete.")
    return summary


# ---------------------------------------------------------------------------
# IP extraction from AI report files
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r'(?:(?:\d{1,3}\.){3}\d{1,3})|(?:[0-9a-fA-F:]{3,})')


def extract_ips_from_file(file_path: str) -> List[str]:
    """
    Read an AI-generated report file and extract all valid IPv4/IPv6 addresses.
    Returns a sorted list of unique IPs.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception as e:
        print(f"[ERROR] Could not read file: {e}")
        return []

    found: set = set()
    for match in _IP_RE.findall(text):
        try:
            ipaddress.ip_address(match)
            found.add(match)
        except ValueError:
            continue

    print(f"[INFO] Extracted {len(found)} unique IPs from {file_path}")
    return sorted(found)
