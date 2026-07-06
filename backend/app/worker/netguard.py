"""Worker-process network guard.

The test engine issues outbound HTTP requests from many call sites (OCSP
checks, CRL downloads discovered from AIA/CDP extensions, P7C fetches...).
Rather than editing every call site, the worker patches
``requests.Session.send`` once at startup so *every* outbound request —
including each individual redirect hop — is validated against the SSRF
policy, capped in timeout, and capped in response size.

This runs only inside the per-run worker subprocess, never in the API server.
"""

from __future__ import annotations

from typing import Callable, Optional

import requests

from ..ssrf import (
    BlockedTargetError,
    NetworkPolicy,
    install_pinning_resolver,
    validate_url,
)

_installed = False


def install(policy: NetworkPolicy, log: Optional[Callable[[str, str], None]] = None) -> None:
    """Patch requests so the policy applies to all engine traffic.

    ``log(level, message)`` receives one line per blocked request.
    """
    global _installed
    if _installed:
        return
    _installed = True

    # Validate at DNS-resolution time too, so the address the socket actually
    # connects to is policy-approved — this closes the DNS-rebinding gap for
    # requests *and* for the curl/openssl subprocesses the engine shells out to.
    install_pinning_resolver(policy, log)

    original_send = requests.Session.send

    def guarded_send(self: requests.Session, request: requests.PreparedRequest, **kwargs):
        url = request.url or ""
        try:
            validate_url(url, policy)
        except BlockedTargetError as exc:
            if log:
                log("WARN", f"[NETGUARD] Blocked outbound request to {url}: {exc.reason}")
            raise

        # Cap the timeout: never allow an unbounded or excessive wait.
        timeout = kwargs.get("timeout")
        cap = policy.max_timeout_seconds
        if timeout is None:
            kwargs["timeout"] = cap
        elif isinstance(timeout, (int, float)) and timeout > cap:
            kwargs["timeout"] = cap

        # Redirect policy: hops are re-validated here because requests calls
        # send() again for every redirect target.
        if not policy.allow_redirects:
            kwargs["allow_redirects"] = False

        # Stream so the size cap is enforced before the body is fully read.
        kwargs["stream"] = True
        response = original_send(self, request, **kwargs)

        if not policy.allow_redirects and response.is_redirect:
            location = response.headers.get("Location", "?")
            response.close()
            if log:
                log("WARN", f"[NETGUARD] Refused to follow redirect {url} -> {location}")
            raise BlockedTargetError(url, f"server redirected to {location}; redirects are disabled by policy")

        content_length = response.headers.get("Content-Length")
        if content_length and content_length.isdigit() and int(content_length) > policy.max_response_bytes:
            response.close()
            raise BlockedTargetError(url, f"response Content-Length {content_length} exceeds limit")

        # Materialize at most max_response_bytes + 1.
        chunks = []
        read = 0
        for chunk in response.iter_content(chunk_size=65536):
            chunks.append(chunk)
            read += len(chunk)
            if read > policy.max_response_bytes:
                response.close()
                raise BlockedTargetError(url, f"response body exceeded {policy.max_response_bytes} byte limit")
        response._content = b"".join(chunks)
        response._content_consumed = True
        return response

    requests.Session.send = guarded_send  # type: ignore[method-assign]
