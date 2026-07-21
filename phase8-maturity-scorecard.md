# Phase 8 — CISA Zero Trust Maturity Model v2.0 Self-Assessment (v2)

**Scored against:** CISA ZTMM v2.0 (April 2024) — 5 pillars × 4 stages (Traditional → Initial → Advanced → Optimal)

**Architecture assessed:** nginx + oauth2-proxy + authz-bridge + OPA (Phase 4+), WireGuard + nftables (Phase 0/3), Authentik OIDC (Phase 1), osquery posture (Phase 2)

## Scorecard

| Pillar | Stage | Justification (traceable to a specific phase's definition-of-done) | Highest-Leverage Next Step |
|--------|-------|---------------------------------------------------------------------|---------------------------|
| **Identity** | Advanced | Authentik OIDC with phishing-resistant WebAuthn MFA (Phase 1 DoD: password alone explicitly fails), 20-min session verified by waiting, session validation at PEP layer via oauth2-proxy (Phase 4 DoD: auth_time-check OPA policy verified), step-up auth for /sensitive (Phase 5 DoD: last-auth-time check confirmed operational) | Add continuous authentication with risk-based step-up (anomalous location/device triggers additional factor) to reach Optimal |
| **Devices** | Advanced | Osquery-based posture checks for disk encryption, patch age, blocklisted processes (Phase 2 DoD: fail-closed verified, manual force of both states); automated revocation on posture failure (Phase 6 DoD: triggers verified); device presence gates network access via WireGuard peer approval (Phase 3 DoD: no tunnel = no app access) | Add hardware-rooted attestation (TPM 2.0 measured boot, device identity certs) to eliminate pure-software reporting and reach Optimal |
| **Networks** | Advanced | WireGuard segmentation with default-deny nftables (Phase 0 DoD: nftables survives reboot, attacker can reach only gateway:443); app reachable only via wg0 regardless of subnet (Phase 3 DoD: trusted-net device without tunnel cannot reach app); separate trusted/untrusted libvirt networks with no direct route | Implement per-application microsegmentation (one WireGuard tunnel per workload instead of per-VM) |
| **Applications & Workloads** | Advanced | nginx as PEP transport with auth_request → authz-bridge → OPA (Phase 4 DoD: OPA denies unhealthy device, both allow/deny verified via curl before browser); Rego policy with MFA + posture + auth_time + ABAC data classification checks; Flask demo app with no local auth logic (correct trust-the-PEP pattern); attack simulation confirms all 4 bypass attempts blocked (Phase 7); signed posture integrity prevents spoofing | Add SPIFFE/SPIRE workload identity (mTLS between services) to reach Optimal |
| **Data** | Initial | Data classification labels at the object level enforced via ABAC in OPA Rego policy. `input.data.classification` is evaluated against user role clearance (admin=3, devops=2, user=1, anonymous=0). Critical/restricted/internal/public tiers are gated by Rego rules alongside existing auth_time + posture checks. Route-level enforcement independently verified (Phase 5 DoD). The shared HMAC key for posture signing is a documented weakness. | Replace shared symmetric posture HMAC with per-device asymmetric keys and implement per-field encryption for restricted/critical data |

## Summary

```
Identity       ████████████████████░░░░  Advanced
Devices        ████████████████████░░░░  Advanced
Networks       ████████████████████░░░░  Advanced
Applications   ████████████████████░░░░  Advanced
Data           ██████░░░░░░░░░░░░░░░░░░  Initial
               ────────────────────────
Overall        ██████████████████░░░░░░  Advanced (weighted)
```

**Strongest:** Networks + Identity — the WireGuard-gated nftables segmentation (Phase 3) and Authentik+oauth2-proxy OIDC with MFA enforcement (Phase 1+4) are the most thoroughly tested layers.

**Weakest:** Data — ABAC now exists at the OPA policy level but relies on the application correctly populating `input.data.classification`. The shared symmetric HMAC key for posture signing remains a weakness (a key compromise breaks all devices).

**Fastest path to Optimal:** Add hardware attestation (Devices pillar via TPM 2.0) and SPIFFE/SPIRE workload identity (Applications pillar). Both achievable without changing the data model.

**Longest path:** Data pillar — per-field encryption for restricted/critical data and replacing shared symmetric HMAC with per-device asymmetric keys are the remaining gaps. This separates portfolio projects from production zero-trust.

## Phase Traceability

| Pillar | Verifies In | Key Verified Behavior |
|--------|-------------|----------------------|
| Identity | Phase 1, Phase 4, Phase 5, Phase 7 | Password-alone fails, MFA required, 20-min expiry, auth_time check, session replay blocked |
| Devices | Phase 2, Phase 3, Phase 6, Phase 7 | Posture fail-closed, manual force test, revocation, posture spoofing blocked |
| Networks | Phase 0, Phase 3, Phase 7 | Default-deny persists, WireGuard gating, direct access blocked |
| Applications | Phase 4, Phase 5, Phase 7, Priority 2.3 | OPA allow/deny verified, step-up auth, all 4 bypass attempts blocked, signed posture |
| Data | Phase 5, Phase 7, Priority 3.7 | Route-level control works, ABAC with data classification in Rego |
