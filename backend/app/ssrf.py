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
from typing import Callable, Iterable, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

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


def _normalize(ip: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    """Collapse an IPv4-mapped IPv6 address (``::ffff:169.254.169.254``) to its
    IPv4 form so classification cannot be evaded by the mapped spelling. On a
    dual-stack host the kernel routes the mapped form to the IPv4 destination,
    so it must be judged as that IPv4 address."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _is_metadata(ip: ipaddress._BaseAddress) -> bool:
    return str(_normalize(ip)) in METADATA_ADDRESSES


def _classify_ip(ip: ipaddress._BaseAddress) -> Optional[str]:
    """Return a block reason for the address, or None if publicly routable."""
    ip = _normalize(ip)
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


def address_block_reason(ip: ipaddress._BaseAddress, policy: NetworkPolicy) -> Optional[str]:
    """Reason this address violates ``policy``, or None if it may be contacted.
    Metadata endpoints stay blocked even in lab mode; other private/loopback
    ranges are permitted only when ``allow_private`` is set."""
    reason = _classify_ip(ip)
    if reason is None:
        return None
    if _is_metadata(ip):
        return reason  # never reachable, even in lab mode
    if not policy.allow_private:
        return reason
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


def resolve_and_validate(url: str, policy: NetworkPolicy) -> List[str]:
    """Validate ``url`` against ``policy`` and return the resolved IP strings
    that passed (so a caller can *pin* the connection to one of them and defeat
    DNS rebinding). Raises BlockedTargetError on any violation.

    Returns an empty list for the lab-mode ``localhost`` shortcut (the caller
    then connects normally); every other host must resolve to at least one
    allowed address.
    """
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
        return []  # explicitly allowed in lab mode; connect normally

    # Literal IP or DNS name: every resolved address must pass the policy.
    allowed: List[str] = []
    for ip in resolve_host(host):
        reason = address_block_reason(ip, policy)
        if reason is not None:
            _block(url, f"{ip}: {reason}")
        allowed.append(str(_normalize(ip)))
    return allowed


def validate_url(url: str, policy: NetworkPolicy) -> None:
    """Raise BlockedTargetError when the URL violates policy. Logs every block."""
    resolve_and_validate(url, policy)


def _block(url: str, reason: str) -> None:
    logger.warning("blocked outbound target", extra={"target": url, "reason": reason})
    raise BlockedTargetError(url, reason)


def validate_urls(urls: Iterable[str], policy: NetworkPolicy) -> None:
    for url in urls:
        validate_url(url, policy)


_resolver_installed = False


def install_pinning_resolver(
    policy: NetworkPolicy, log: Optional[Callable[[str, str], None]] = None
) -> None:
    """Replace ``socket.getaddrinfo`` process-wide with one that drops any
    address the policy forbids.

    Because the connection can only ever be handed policy-approved addresses,
    this closes the validate-then-reconnect DNS-rebinding gap uniformly for
    *every* outbound client in the process — ``requests``, and the ``curl`` /
    ``openssl`` subprocesses the engine shells out to (a second resolution at
    connect time is validated exactly like the first). Intended for the
    single-purpose per-run worker subprocess only; never install this in the
    API server, whose threads serve unrelated traffic.
    """
    global _resolver_installed
    if _resolver_installed:
        return
    _resolver_installed = True

    original = socket.getaddrinfo

    def guarded_getaddrinfo(host, *args, **kwargs):
        results = original(host, *args, **kwargs)
        allowed = []
        for res in results:
            raw = res[4][0]
            try:
                addr = ipaddress.ip_address(raw)
            except ValueError:
                allowed.append(res)
                continue
            reason = address_block_reason(addr, policy)
            if reason is None:
                allowed.append(res)
            elif log:
                log("WARN", f"[NETGUARD] blocked resolved address {raw} for {host!r}: {reason}")
        if not allowed:
            raise socket.gaierror(f"all addresses for {host!r} are blocked by the SSRF policy")
        return allowed

    socket.getaddrinfo = guarded_getaddrinfo  # type: ignore[assignment]


def guarded_fetch(
    url: str,
    policy: NetworkPolicy,
    *,
    timeout: int,
    max_bytes: int,
    max_redirects: int = 5,
) -> bytes:
    """Fetch ``url`` with the SSRF policy enforced on the initial request **and
    on every redirect hop**, plus a hard response-size cap.

    The API process (unlike the per-run worker) has no ``requests`` net-guard
    installed, so redirects must be followed manually: ``requests`` would
    otherwise follow a ``Location`` to an internal/metadata address that was
    never passed through :func:`validate_url`. Each hop is validated before a
    socket is opened to it, and auto-redirects are disabled.
    """
    import requests

    current = url
    for _ in range(max_redirects + 1):
        allowed = resolve_and_validate(current, policy)
        # Pin the connection to a validated IP so a rebinding DNS server cannot
        # swap in an internal address between validation and connect. For http
        # we connect to the IP and carry the original Host header; for https we
        # keep the hostname (TLS verification of the presented certificate is
        # itself the pin — a rebind to an internal host fails cert validation).
        parsed = urlparse(current)
        connect_url, headers = current, {}
        if allowed and parsed.scheme == "http":
            ip = allowed[0]
            netloc = f"[{ip}]" if ":" in ip else ip
            if parsed.port:
                netloc += f":{parsed.port}"
            connect_url = urlunparse(parsed._replace(netloc=netloc))
            headers["Host"] = parsed.netloc
        response = requests.get(
            connect_url, headers=headers, timeout=timeout, stream=True, allow_redirects=False
        )
        try:
            if response.is_redirect:
                location = response.headers.get("Location")
                if not location:
                    raise BlockedTargetError(current, "redirect response without a Location header")
                current = requests.compat.urljoin(current, location)
                continue
            response.raise_for_status()
            chunks: List[bytes] = []
            read = 0
            for chunk in response.iter_content(chunk_size=65536):
                chunks.append(chunk)
                read += len(chunk)
                if read > max_bytes:
                    raise ValueError(f"response exceeded {max_bytes} byte limit")
            return b"".join(chunks)
        finally:
            response.close()
    raise BlockedTargetError(url, f"exceeded {max_redirects} redirects")
