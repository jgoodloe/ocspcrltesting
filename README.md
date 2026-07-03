# ocspcrltesting

Web-based OCSP / CRL / certificate-path testing tool — the browser version of
[jgoodloe/OCSPTesting](https://github.com/jgoodloe/OCSPTesting), packaged for
Docker and nginx.

```bash
docker compose up --build
# open http://localhost:8080/
```

**Start here → [README_WEB.md](README_WEB.md)** (architecture, local
development, configuration).

- [docs/API.md](docs/API.md) — REST/WebSocket API
- [docs/DEPLOYMENT_NGINX.md](docs/DEPLOYMENT_NGINX.md) — root and `/ocsp/` subpath deployment
- [docs/SECURITY.md](docs/SECURITY.md) — SSRF policy, auth, key handling
- `cli.py` — headless CLI for the same test engine
- `ocsp_tester/` — the test engine (from OCSPTesting, GUI-free)
