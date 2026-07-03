"""Outbound target validation (SSRF protection).

The tool's whole purpose is to make requests to user-supplied OCSP and CRL
URLs, so it is an SSRF vector by design. By default we refuse targets that
resolve to loopback, link-local, RFC1918/ULA private space, or cloud metadata
addresses. ``OCSPWEB_ALLOW_PRIVATE_TARGETS=true`` relaxes this for internal
lab deployments; loopback and metadata endpoints stay blocked even then
unless the hostname is explicitly what the operator asked for is loopback.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("ocspweb.ssrf")

METADATA_ADDRESSES = {
    "169.254.169.254",  # AWS/GCP/Azure IMDS
    "fd00:ec2::254",    # AWS IMDSv2 IPv6
    "100.100.100.200",  # Alibaba
}


class BlockedTargetError(Exception):
    """Raised when an outbound target violates the network policy."""

    def __init__(self, url: str, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(f"Blocked outbound request to {url}: {reason}")


@dataclass
class NetworkPolicy:
    allow_private: bool = False
    allow_redirects: bool = False
    max_response_bytes: int = 10 * 1024 * 1024
    max_timeout_seconds: int = 60
    blocked_hosts: Tuple[str, ...] = ()

    @classmethod
    def from_settings(cls, settings) -> "NetworkPolicy":
        return cls(
            allow_private=settings.allow_private_targets,
            allow_redirects=settings.allow_redirects,
            max_response_bytes=settings.max_response_bytes,
            max_timeout_seconds=settings.max_request_timeout_seconds,
            blocked_hosts=tuple(settings.extra_blocked_host_list),
        )


def _classify_ip(ip: ipaddress._BaseAddress) -> Optional[str]:
    """Return a block reason for the address, or None if publicly routable."""
    if str(ip) in METADATA_ADDRESSES:
        return "cloud metadata service address"
    if ip.is_loopback:
        return "loopback address"
    if ip.is_link_local:
        return "link-local address"
    if ip.is_private:
        return "private network address (RFC1918/ULA)"
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return "non-unicast or reserved address"
    return None


def resolve_host(host: str) -> List[ipaddress._BaseAddress]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise BlockedTargetError(host, f"DNS resolution failed: {exc}") from exc
    addresses = []
    for info in infos:
        try:
            addresses.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    if not addresses:
        raise BlockedTargetError(host, "hostname resolved to no usable addresses")
    return addresses


def validate_url(url: str, policy: NetworkPolicy) -> None:
    """Raise BlockedTargetError when the URL violates policy. Logs every block."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        _block(url, f"unsupported scheme '{parsed.scheme}' (unix sockets/file/ftp are not allowed)")
    host = parsed.hostname
    if not host:
        _block(url, "URL has no host")
    host_l = host.lower()
    if host_l in policy.blocked_hosts:
        _block(url, "host is on the operator block list")
    if host_l == "localhost" or host_l.endswith(".localhost"):
        if not policy.allow_private:
            _block(url, "localhost is blocked by policy")
        return  # explicitly allowed in lab mode

    # Literal IP or DNS name: every resolved address must pass the policy.
    for ip in resolve_host(host):
        reason = _classify_ip(ip)
        if reason is None:
            continue
        # Metadata endpoints stay blocked even in lab mode.
        if str(ip) in METADATA_ADDRESSES:
            _block(url, f"{ip}: {reason}")
        if not policy.allow_private:
            _block(url, f"{ip}: {reason}")


def _block(url: str, reason: str) -> None:
    logger.warning("blocked outbound target", extra={"target": url, "reason": reason})
    raise BlockedTargetError(url, reason)


def validate_urls(urls: Iterable[str], policy: NetworkPolicy) -> None:
    for url in urls:
        validate_url(url, policy)
