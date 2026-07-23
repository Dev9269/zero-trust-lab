"""Health check and connection timeout utilities for gateway services."""

import socket
import time
from typing import Optional


def wait_for_port(
    host: str, port: int, timeout: int = 30, interval: float = 1.0
) -> bool:
    """Block until a TCP port is reachable or timeout expires."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=interval):
                return True
        except (OSError, socket.timeout):
            time.sleep(interval)
    return False


def check_http_ready(
    url: str, expected_status: int = 200, timeout: int = 10
) -> Optional[int]:
    """Quick HTTP readiness check returning status code or None."""
    try:
        import urllib.request

        resp = urllib.request.urlopen(url, timeout=timeout)
        return resp.status
    except Exception:
        return None
