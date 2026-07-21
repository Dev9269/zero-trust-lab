# ZTLab — Zero Trust Lab

A self-hosted, from-scratch zero-trust access control system running on 4 KVM/libvirt Debian 12 VMs. Built as a learning/portfolio project against the CISA Zero Trust Maturity Model v2.0.

**Architecture correction:** Uses nginx + oauth2-proxy + authz-bridge + OPA (not Pomerium — Pomerium Community doesn't support custom Rego policies, that's Enterprise-only). This is a fully open-source, properly separated PEP/PDP stack.

## Architecture

```
                          untrusted-net (10.10.2.0/24)
                            │
                    ┌───────┘
               ┌────┴────┐
               │ attacker │
               │ 10.10.2.10│
               └────┬────┘
                    │
             gateway:443 (only ingress)
                    │
          ┌─────────┴──────────────────┐
          │         gateway VM         │
          │  10.10.1.1                │
          │                            │
          │  nginx (PEP transport)     │
          │    └── auth_request ──────►│
          │  authz-bridge (PEP logic)  │
          │    ├──► oauth2-proxy (authn)│
          │    ├──► OPA (PDP, authz)   │
          │    └──► posture store      │
          │  WireGuard + nftables      │
          └─────────┬──────────────────┘
                    │ wg0 tunnel
          ┌─────────┴──────────┐
          │                    │
   ┌──────┴──────┐     ┌──────┴──────┐
   │   idp VM    │     │   app VM    │
   │  10.10.1.10 │     │ 10.10.1.20  │
   │  Authentik  │     │  Flask app  │
   │  (OIDC IdP) │     │  /public    │
   └─────────────┘     │  /sensitive │
                        └─────────────┘

```

**Logical flow:** client → nginx:443 → auth_request → authz-bridge → oauth2-proxy (session check) + OPA (Rego policy: MFA + posture + auth_time) → if allow → proxy to Flask app.

## VM Specs

| VM | IP | Role | RAM | Disk |
|----|----|------|-----|------|
| gateway | 10.10.1.1 | PEP/PDP, WireGuard, nftables, logs | 2 GB | 20 GB |
| idp | 10.10.1.10 | Authentik (OIDC identity provider) | 2 GB | 20 GB |
| app | 10.10.1.20 | Protected Flask demo app | 2 GB | 20 GB |
| attacker | 10.10.2.10 | Untrusted client for attack tests | 2 GB | 20 GB |

## Quick Start

```bash
# 1. Define networks
sudo virsh net-define networks/trusted-net.xml && sudo virsh net-start trusted-net
sudo virsh net-define networks/untrusted-net.xml && sudo virsh net-start untrusted-net

# 2. Create VMs (edit scripts/create-vms.sh for your ISO path)
sudo bash scripts/create-vms.sh

# 3. Install Debian 12 minimal on each VM, configure networking

# 4. Follow phases in order:
#    Phase 1: idp VM — Authentik docker-compose, OIDC, WebAuthn
#    Phase 2: client VMs — osquery + posture_check.py
#    Phase 3: gateway + app — WireGuard + nftables
#    Phase 4: gateway — docker compose up (nginx + oauth2-proxy + authz-bridge + OPA)
#    Phase 5: included in docker-compose (Flask demo app)
#    Phase 6: logs + revocation script
#    Phase 7: attacker VM — run 4 bypass tests
#    Phase 8: maturity scorecard
```

Each phase has a detailed checkpoint document with pre-reqs, failure modes, rollback, and definition-of-done checklist. Do not proceed to the next phase until the current one's checklist is complete.

## Phase Map

| Phase | Topic | Key File(s) |
|-------|-------|-------------|
| 0 | Lab environment | `networks/trusted-net.xml`, `gateway/nftables.conf` |
| 1 | Identity (Authentik) | `idp/docker-compose.yml` |
| 2 | Device posture | `scripts/posture_check.py`, `scripts/ztlab-posture.{service,timer}` |
| 3 | Network segmentation (WireGuard) | `gateway/wg0.conf`, `scripts/wg-add-peer.sh` |
| 4 | PEP+PDP (nginx+oauth2-proxy+authz-bridge+OPA) | `gateway/docker-compose.yml`, `gateway/opa/policy.rego`, `gateway/authz-bridge/app.py` |
| 5 | Demo app (Flask) | `app/app.py`, `app/Dockerfile` |
| 6 | Visibility + automation | `scripts/posture_revoker.py` |
| 7 | Attack simulation | `phase7-attack-simulation.md` |
| 8 | Maturity self-assessment | `phase8-maturity-scorecard.md` |

## Key Architecture Decisions

- **Why nginx + oauth2-proxy + authz-bridge instead of Pomerium?** Pomerium Community doesn't support custom Rego policies — that's Enterprise-only. The nginx `auth_request` pattern with a separate authz-bridge service gives us a real, decoupled PDP/PEP separation using only free software.
- **Why a shared JSON file for posture data?** Lab simplicity. The pattern (PEP reads posture at request time and includes it in OPA input) is architecture-identical to a production Redis-backed approach.
- **Why Flask instead of FastAPI?** Simpler for a two-route demo with inline templates. The app is intentionally dumb — it has no auth logic, trusting the upstream PEP.

## Lab Shortcuts (Not Production-Ready)

- **Posture signing uses a shared symmetric key** — the HMAC secret is the same for all devices. A per-device key pair (asymmetric) would be production-grade. The current fix closes the "anyone can write posture.json" gap but a key compromise breaks all devices.
- **Posture store is still a JSON file** — not a database. No query isolation, no atomic writes, no access audit. The HMAC signing prevents forgery but doesn't fix structural weaknesses.
- **No mTLS between services** — internal service auth is done by network segmentation, not by mutual TLS. A process that reaches the compose network can talk to any service without authentication. See `scripts/setup-mtls.sh` for a self-managed local CA approach.
- **Self-signed TLS certs** — OK for lab, do NOT use in production. Replace with Let's Encrypt or an internal CA with automated renewal.
- **No persistent log storage** — Loki data lives in a Docker volume; `docker compose down -v` loses all history. Production needs S3/GCS backend or Loki's `filesystem` config with a host bind mount.
- **OPA :8181 is not exposed by default** — use `docker compose -f docker-compose.yml -f docker-compose.override.yml up` for direct OPA curl testing during development.
- **oauth2-proxy header names are version-dependent** — must verify against installed version before upgrading.
- **Mock re-auth** — `auth_time` comes from the OIDC claim, not from an actual WebAuthn re-prompt. The step-up check enforces policy but the UX flow is simulated.
- **No TPM 2.0 hardware attestation** — device posture is purely software-reported via osquery. A compromised client VM can report healthy posture even when compromised. Production would verify measured boot and disk encryption via TPM 2.0 PCR quotes (see [phase8-maturity-scorecard.md](phase8-maturity-scorecard.md)).
- **No SPIFFE/SPIRE workload identity** — services authenticate each other by network presence, not cryptographic identity. Production would run a SPIRE server with per-service agent attestors and short-lived X.509 SVIDs.
- **No rate limiting or input validation on Flask** — the demo app trusts the upstream PEP, but a misconfigured nginx could allow direct requests. Production would add rate limiting at the nginx layer and input validation on every route.

## Testing

### Python unit tests

```bash
pip install -r requirements-dev.txt
pytest -v
```

### OPA policy tests

```bash
# Install OPA (macOS)
curl -L -o /usr/local/bin/opa https://openpolicyagent.org/downloads/latest/opa_darwin_amd64
chmod +x /usr/local/bin/opa

# Run tests
opa test gateway/opa/ -v
```

### Lint

```bash
flake8 .
```

### All at once

```bash
make test lint
```

## Makefile

Common tasks are available via `make`:

| Command | Description |
|---------|-------------|
| `make test` | Run Python + OPA tests |
| `make lint` | Run flake8 |
| `make build` | Build all Docker images |
| `make up` | Start gateway stack (detached) |
| `make down` | Stop gateway stack |
| `make logs` | Tail gateway stack logs |
| `make clean` | Remove caches |

## Deployment

### Docker images (GHCR)

Pre-built images are published to GitHub Container Registry on each release:

```bash
# Pull images
docker pull ghcr.io/dev9269/ztlab-demo-app:latest
docker pull ghcr.io/dev9269/ztlab-authz-bridge:latest
docker pull ghcr.io/dev9269/ztlab-mock-oidc:latest

# Or use the production override
make prod-up
```

> **Forking?** The docker-publish.yml uses `${{ github.repository_owner }}` so images publish under your namespace automatically. Update the `ghcr.io/dev9269/` paths above and in `gateway/docker-compose.prod.yml` to match your own GHCR namespace.

### Auto-deploy to server

The `deploy.yml` workflow SSHs into your server on every push to `main`. Set these repository secrets:

| Secret | Description |
|--------|-------------|
| `DEPLOY_HOST` | Server IP or hostname |
| `DEPLOY_USER` | SSH username |
| `DEPLOY_SSH_KEY` | Private SSH key (ed25519 recommended) |

The workflow clones/pulls the repo to `/opt/ztlab` and runs `docker compose up -d`.

### GitHub Pages

Documentation is auto-deployed to GitHub Pages on every push to `main`. Enable it in repo Settings > Pages > Source: GitHub Actions.
