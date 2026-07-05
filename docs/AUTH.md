# Authentication, Workspaces & Multi-user

This deployment supports multiple users organised into **workspaces**. Every
test run, saved profile and saved CA certificate belongs to a workspace, and
users are members of workspaces with a role.

If you run the app with **no auth configured**, it stays in the original
single-user "open" mode: an anonymous administrator and a single shared
`Default` workspace. Everything below is opt-in.

## Concepts

- **User** — either an OIDC identity (matched on the stable `sub` claim, never
  email) or a local account. Local accounts are **admin-created only**; there is
  no self-registration. Passwords are hashed with argon2id.
- **Workspace** — owns runs/profiles/CA certs. Two kinds:
  - `personal` — created automatically for each user on first login.
  - `shared` — created by users; members are managed explicitly or synced from
    an OIDC group.
- **Role** — per workspace, one of `viewer` < `member` < `admin`:
  - `viewer` — read runs, profiles, certificates.
  - `member` — everything a viewer can do, plus start/cancel runs and manage
    profiles and CA certificates.
  - `admin` — everything a member can do, plus manage workspace settings and
    members.
- **Global admin** — a user flag (set on the break-glass admin and any accounts
  you promote). Global admins can see and manage every workspace and the
  deployment-wide user list and audit log.
- **Session** — the app issues its own signed session cookie. It is the single
  source of truth; the browser never holds IdP tokens. Sessions are signed with
  `OCSPWEB_SESSION_SECRET`.

## Turning auth on

Set any of these and authentication is enforced (see `.env.example` for the
full list):

```ini
OCSPWEB_SESSION_SECRET=$(openssl rand -hex 32)   # required in production
OCSPWEB_BOOTSTRAP_ADMIN_PASSWORD=change-me       # break-glass local admin
```

At startup the break-glass admin (`OCSPWEB_BOOTSTRAP_ADMIN_USERNAME`, default
`admin`) is created or its password refreshed, and it is always a global admin.
Use it to sign in, then create local users (Admin page) or wire up OIDC.

## OIDC (authentik)

Register an OAuth2/OpenID Connect provider in authentik and set:

```ini
OCSPWEB_OIDC_ISSUER=https://authentik.example.com/application/o/ocsp/
OCSPWEB_OIDC_CLIENT_ID=...
OCSPWEB_OIDC_CLIENT_SECRET=...
OCSPWEB_OIDC_SCOPES=openid email profile
OCSPWEB_OIDC_GROUP_CLAIM=groups
```

The redirect/callback URL to register is:

```
<public-base-url><base-path>/api/auth/oidc/callback
```

e.g. `https://ocsp.example.com/api/auth/oidc/callback`. Set
`OCSPWEB_PUBLIC_BASE_URL` when the app can't infer its external URL from the
request (behind some proxies).

On first login an OIDC user is provisioned with a personal workspace. If a
shared workspace has an `oidc_group` matching one of the user's groups, they are
added to it as a `member` automatically.

To force SSO-only, set `OCSPWEB_LOCAL_LOGIN_ENABLED=false` (the break-glass
admin still works for recovery).

## API tokens

Each user can mint personal API tokens (API tokens page). A token:

- is shown once at creation and stored only as a SHA-256 hash,
- carries a **role ceiling** it can never exceed,
- may be scoped to a single workspace,
- is revocable at any time.

Use it as a bearer token:

```bash
curl -H "Authorization: Bearer ocspt_..." \
     "https://ocsp.example.com/api/test-runs?workspace_id=3"
```

## Per-workspace policy, capped by the deployment

Two deployment settings are **hard ceilings**:

- `OCSPWEB_ALLOW_PRIVATE_TARGETS` — a workspace may enable private/loopback
  OCSP/CRL targets only if this is `true`.
- `OCSPWEB_MAX_CONCURRENT_RUNS` — a workspace's own concurrency limit is capped
  by this value.

## Audit log

Logins, workspace/member/token/user changes are appended to an audit log.
Workspace admins see their workspace's activity (workspace settings page);
global admins see everything (Admin page).

## Migrations

The schema is created automatically at startup (SQLite and PostgreSQL alike).
For controlled PostgreSQL upgrades, Alembic migrations are provided:

```bash
cd backend
alembic upgrade head        # reads OCSPWEB_DATABASE_URL
```

Alembic uses batch mode for SQLite and a synchronous psycopg2 connection for
PostgreSQL. See `backend/migrations/`.
