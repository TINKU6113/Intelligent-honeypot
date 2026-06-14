"""
ip_blocker_client.py
--------------------
Client-side helpers:

1. send_block_request(ip, host, port)
   — sends an IP address over TCP to the socket_server for blocking.

2. prompt_and_block(ip, host, port)
   — interactive CLI prompt: asks the user whether to block, then calls
     send_block_request if confirmed.

3. block_ip(ip)  [local stub]
   — called by socket_server.py on the *receiver* side to actually apply
     the firewall rule. Adapt this to iptables / Windows Firewall / etc.
"""

import ipaddress
import logging
import socket
import subprocess
import sys

log = logging.getLogger(__name__)

DEFAULT_RECEIVER_HOST = "127.0.0.1"
DEFAULT_RECEIVER_PORT = 5002


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _is_valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s.strip())
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Client: send an IP to the remote blocking server
# ---------------------------------------------------------------------------

def send_block_request(
    ip: str,
    receiver_host: str = DEFAULT_RECEIVER_HOST,
    receiver_port: int = DEFAULT_RECEIVER_PORT,
    timeout: int = 5,
) -> bool:
    """
    Open a TCP connection to receiver_host:receiver_port and send ip.
    Returns True on success, False on failure.
    """
    if not _is_valid_ip(ip):
        log.error("Invalid IP address: %r", ip)
        return False
    try:
        with socket.create_connection((receiver_host, receiver_port), timeout=timeout) as s:
            s.sendall(ip.strip().encode("utf-8"))
        log.info("Block request sent: %s → %s:%d", ip, receiver_host, receiver_port)
        return True
    except Exception as e:
        log.error("Could not send block request for %s: %s", ip, e)
        return False


def prompt_and_block(
    ip: str,
    receiver_host: str = DEFAULT_RECEIVER_HOST,
    receiver_port: int = DEFAULT_RECEIVER_PORT,
) -> None:
    """
    Interactively ask the operator whether to block ip.
    If confirmed, call send_block_request().
    """
    if not ip:
        print("[ERROR] No IP provided.")
        return

    choice = input(f"Block IP {ip}? (yes/no): ").strip().lower()
    if choice not in ("yes", "y"):
        print(f"[INFO] Skipping block for {ip}.")
        return

    ok = send_block_request(ip, receiver_host=receiver_host, receiver_port=receiver_port)
    if ok:
        print(f"[INFO] Block request sent for {ip}.")
    else:
        print(f"[WARN] Failed to send block request for {ip}. Check server.")


# ---------------------------------------------------------------------------
# Server-side stub: actually apply the firewall rule
# Runs on the machine that received the IP via socket_server.py
# ---------------------------------------------------------------------------

def block_ip(ip: str) -> bool:
    """
    Apply a local firewall DROP rule for ip.
    Currently supports Linux iptables.
    Extend for Windows Firewall, nftables, pfctl, etc.
    Returns True on success.
    """
    if not _is_valid_ip(ip):
        log.warning("block_ip: invalid IP %r — skipping.", ip)
        return False

    if sys.platform.startswith("linux"):
        return _block_iptables(ip)
    else:
        log.warning(
            "block_ip: platform %r not supported; add your own rule here.", sys.platform
        )
        return False


def _block_iptables(ip: str) -> bool:
    """Drop all inbound packets from ip using iptables (Linux)."""
    try:
        result = subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            log.info("iptables DROP rule added for %s", ip)
            return True
        log.error("iptables error for %s: %s", ip, result.stderr.strip())
        return False
    except Exception as e:
        log.error("iptables call failed for %s: %s", ip, e)
        return False
