# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

## Reporting a Vulnerability

This project is a **lab environment** intended for learning and experimentation.
If you discover a security vulnerability, please **do not open a public issue**.

Instead, disclose responsibly by emailing the maintainer at the address listed
on the repository profile. You should receive an acknowledgment within 72 hours.

### What to include

- A description of the vulnerability.
- Steps to reproduce (PoC or minimal setup).
- Affected components and versions.
- Any proposed fix (optional).

We will coordinate a fix and release before public disclosure.

## SSH Key Rotation Policy

Maintainers using the `deploy.yml` GitHub Actions workflow:
1. Generate a new ed25519 key pair: `ssh-keygen -t ed25519 -f deploy-key -C "github-actions-deploy"`
2. Add the public key to the target server's `~/.ssh/authorized_keys`
3. Update the `DEPLOY_SSH_KEY` repository secret with the **private** key
4. Revoke the old key from the server's `authorized_keys`
5. Rotate at least every **90 days**, or immediately after any team member with access departs

This project does not rotate SSH keys automatically. Use GitHub's secret scanning
alerts to detect leaked keys — enable it in repo Settings > Security > Secret scanning.
