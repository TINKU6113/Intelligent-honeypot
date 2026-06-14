"""
socket_server.py
----------------
Lightweight TCP socket server that listens for incoming IP addresses
and invokes the local firewall blocker for each one.

Run this on the machine that owns the firewall (e.g., the honeypot host):

    python -m response_engine.socket_server

Default listen address: 0.0.0.0:5002
"""

import ipaddress
import logging
import socket
import threading
from typing import Callable, Optional

from response_engine.ip_blocker import block_ip

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [socket_server] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5002
BUFFER_SIZE  = 256


def _validate_ip(raw: str) -> Optional[str]:
    """Return cleaned IP string if valid, else None."""
    ip = raw.strip()
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        return None


def _handle_client(
    conn: socket.socket,
    addr: tuple,
    block_fn: Callable[[str], bool],
) -> None:
    """Receive one IP from the client and block it."""
    with conn:
        try:
            raw = conn.recv(BUFFER_SIZE).decode("utf-8", errors="ignore")
            ip = _validate_ip(raw)
            if not ip:
                log.warning("Received invalid IP from %s: %r — ignored.", addr, raw)
                return
            log.info("Received block request from %s: %s", addr, ip)
            success = block_fn(ip)
            if success:
                log.info("Blocked %s successfully.", ip)
            else:
                log.warning("Blocking %s returned failure.", ip)
        except Exception as e:
            log.error("Error handling client %s: %s", addr, e)


def start_server(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    block_fn: Callable[[str], bool] = block_ip,
) -> None:
    """
    Start the blocking receiver server (blocking call — runs forever).
    Each connection is handled in a daemon thread.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(10)
        log.info("Listening for block requests on %s:%d …", host, port)

        while True:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=_handle_client,
                args=(conn, addr, block_fn),
                daemon=True,
            )
            t.start()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Honeypot IP block receiver")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    start_server(host=args.host, port=args.port)
