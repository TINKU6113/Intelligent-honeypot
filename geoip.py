"""
geoip.py
--------
GeoIP helpers: pretty-print geo information about an IP,
and print a concise human-readable probe summary.
"""

import json
import pprint
from typing import Any, Dict, Optional


def print_probe_summary(summary: Dict[str, Any], outpath: Optional[str] = None) -> None:
    """
    Print a human-friendly summary from a run_full_probes() result dict.
    Optionally save the full JSON to outpath.
    """
    ip = summary.get("ip", "?")
    print("\n=== PROBE SUMMARY ===")
    print(f"IP : {ip}")
    print(f"At : {summary.get('collected_at', '')}")

    # Reverse DNS
    rdns = summary["probes"].get("reverse_dns", {})
    if "hostname" in rdns:
        print(f"rDNS: {rdns['hostname']}")

    # GeoIP
    geo = summary["probes"].get("geoip", {})
    ipinfo = geo.get("ipinfo") or {}
    ipapi  = geo.get("ipapi") or {}
    if ipinfo:
        loc = f"{ipinfo.get('city','')} {ipinfo.get('region','')} {ipinfo.get('country','')}"
        org = ipinfo.get("org", "")
        print(f"Geo (ipinfo): {loc.strip()}  |  Org: {org}")
    elif ipapi:
        loc = f"{ipapi.get('city','')} {ipapi.get('regionName','')} {ipapi.get('country','')}"
        isp = ipapi.get("isp", "")
        print(f"Geo (ip-api): {loc.strip()}  |  ISP: {isp}")

    # Ping
    ping = summary["probes"].get("ping", {})
    if ping.get("rc", -1) == 0:
        print("Ping : reachable ✅")
    else:
        print(f"Ping : unreachable / {ping.get('stderr','')}")

    # Banner snippets
    for port, data in summary["probes"].get("banners", {}).items():
        snippet = (
            data.get("banner")
            or data.get("connect_error")
            or data.get("error", "")
        )
        if snippet:
            print(f"Port {port}: {snippet[:160].replace(chr(10),' ').strip()}")

    # Whois note
    whois = summary["probes"].get("whois", {})
    if whois.get("rc", -1) >= 0 and whois.get("stdout"):
        print("Whois: obtained (see full JSON)")

    print("=== END SUMMARY ===\n")

    if outpath:
        with open(outpath, "w", encoding="utf-8") as fh:
            json.dump(summary, fh, indent=2, ensure_ascii=False)
        print(f"Full probe JSON saved → {outpath}")

    # Also pretty-print to console
    pprint.pprint(summary)


def get_country(summary: Dict[str, Any]) -> str:
    """Extract country code from a probe summary (best-effort)."""
    geo = summary.get("probes", {}).get("geoip", {})
    return (
        (geo.get("ipinfo") or {}).get("country")
        or (geo.get("ipapi") or {}).get("countryCode")
        or "??"
    )


def get_org(summary: Dict[str, Any]) -> str:
    """Extract org/ISP from a probe summary (best-effort)."""
    geo = summary.get("probes", {}).get("geoip", {})
    return (
        (geo.get("ipinfo") or {}).get("org")
        or (geo.get("ipapi") or {}).get("isp")
        or "unknown"
    )
