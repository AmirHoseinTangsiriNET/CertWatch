"""Optional enrichment. Kept separate so the detector stays pure."""
from __future__ import annotations

import socket
from typing import List


def resolve_ips(domain: str) -> List[str]:
    """Return the sorted A/AAAA addresses of ``domain`` (empty list if it does not resolve)."""
    try:
        infos = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError, OSError):
        return []
    return sorted({info[4][0] for info in infos})
