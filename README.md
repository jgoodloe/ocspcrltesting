# ocspcrltesting

Web-based OCSP / CRL / certificate-path testing tool — the browser version of
[jgoodloe/OCSPTesting](https://github.com/jgoodloe/OCSPTesting), packaged for
Docker and nginx.

```bash
docker compose up --build
# open http://localhost:8080/
```

> ⚠️ **Runs unauthenticated by default.** With no auth configured (the shipped
> compose leaves `OCSPWEB_SESSION_SECRET` and `OCSPWEB_BOOTSTRAP_ADMIN_PASSWORD`
> empty), the app runs open as a single anonymous **global admin** and makes
> outbound requests to user-supplied URLs. Keep it on localhost / an isolated
> lab, or enable authentication and TLS before exposing it — see
> [docs/AUTH.md](docs/AUTH.md) and [docs/SECURITY.md](docs/SECURITY.md).

**Start here → [README_WEB.md](README_WEB.md)** (architecture, local
development, configuration).

- [docs/API.md](docs/API.md) — REST/WebSocket API
- [docs/DEPLOYMENT_NGINX.md](docs/DEPLOYMENT_NGINX.md) — root and `/ocsp/` subpath deployment
- [docs/SECURITY.md](docs/SECURITY.md) — SSRF policy, auth, key handling
- `cli.py` — headless CLI for the same test engine
- `ocsp_tester/` — the test engine (from OCSPTesting, GUI-free)
