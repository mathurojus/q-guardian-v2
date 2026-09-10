"""
Network / filesystem safety guards for Q-Guardian scanners.

Two abuse surfaces are closed here:
  1. SSRF — active network/API scanners must not be pointed at loopback,
     private, link-local (incl. cloud metadata 169.254.169.254) or reserved
     addresses unless ALLOW_PRIVATE_SCAN_TARGETS is explicitly set.
  2. Path traversal / arbitrary file read — local-path scanners must not open
     files outside SCAN_ROOT (when configured) or in sensitive system locations.
"""

import ipaddress
import os
import socket
from typing import Optional
from urllib.parse import urlparse

from app.settings import ALLOW_PRIVATE_SCAN_TARGETS, SCAN_ROOT


class TargetNotAllowed(ValueError):
    """Raised when a scan target fails an SSRF or path-confinement check."""


def _host_from_target(target: str) -> str:
    target = (target or "").strip()
    if "://" in target:
        return urlparse(target).hostname or ""
    # bare host[:port]
    return target.split("/")[0].split(":")[0]


def is_public_host(host: str) -> bool:
    """True if host resolves to a globally-routable address (or can't be
    resolved — then it's the OS's problem, not an internal pivot)."""
    if not host:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return True  # unresolvable: not an internal target we can reach
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_reserved or addr.is_multicast or addr.is_unspecified:
            return False
    return True


def assert_target_allowed(target: str) -> str:
    """Validate an active-scan network target. Returns the host, or raises."""
    host = _host_from_target(target)
    if not host:
        raise TargetNotAllowed("Empty or unparseable scan target.")
    if ALLOW_PRIVATE_SCAN_TARGETS:
        return host
    if not is_public_host(host):
        raise TargetNotAllowed(
            f"Target '{host}' resolves to a private/loopback/link-local address. "
            "Refusing (set ALLOW_PRIVATE_SCAN_TARGETS=true to override for hosts you own)."
        )
    return host


# Sensitive locations blocked even when SCAN_ROOT is not configured.
_SENSITIVE_SEGMENTS = (
    os.sep + "windows" + os.sep, os.sep + "system32" + os.sep,
    os.sep + "etc" + os.sep, os.sep + "proc" + os.sep, os.sep + "sys" + os.sep,
    os.sep + ".ssh" + os.sep, os.sep + ".aws" + os.sep,
)
_SENSITIVE_NAMES = {"shadow", "passwd", "sam", "pagefile.sys", "id_rsa", ".env"}


def resolve_scan_path(path: str) -> str:
    """Return a safe real path for a local-path scan, or raise TargetNotAllowed.

    - rejects http(s)/UNC targets
    - when SCAN_ROOT is set, confines strictly under it (realpath + commonpath)
    - otherwise blocks sensitive system paths as a baseline
    """
    raw = (path or "").strip()
    if not raw:
        raise TargetNotAllowed("Empty scan path.")
    if raw.startswith(("http://", "https://", "//", "\\\\")):
        raise TargetNotAllowed("Remote/UNC paths are not accepted for local scans.")

    real = os.path.realpath(raw)

    if SCAN_ROOT:
        root = os.path.realpath(SCAN_ROOT)
        try:
            if os.path.commonpath([root, real]) != root:
                raise TargetNotAllowed(f"Path escapes SCAN_ROOT ({root}).")
        except ValueError:
            # commonpath raises across drives on Windows
            raise TargetNotAllowed(f"Path is outside SCAN_ROOT ({root}).")
        return real

    low = real.lower()
    if any(seg in low for seg in _SENSITIVE_SEGMENTS) or os.path.basename(low) in _SENSITIVE_NAMES:
        raise TargetNotAllowed("Refusing to scan a sensitive system path.")
    return real
