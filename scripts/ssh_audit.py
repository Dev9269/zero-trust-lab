#!/usr/bin/env python3
"""
ssh_audit.py — SSH key inventory and change detection.

Collects SSH host key fingerprints and authorized_keys for all users,
writes the result to a JSON file for the control plane to consume.

Run periodically (e.g., daily via systemd timer). The output file can be
compared with previous runs to detect unauthorized key additions.

Usage:
  python3 ssh_audit.py [--output /path/to/ssh-audit.json]
"""

import grp
import json
import os
import pwd
import subprocess
import sys
import time

SSH_AUDIT_PATH = os.environ.get("SSH_AUDIT_PATH", "/shared/ssh-audit.json")


def get_host_key_fingerprints() -> list[dict]:
    results = []
    for f in os.listdir("/etc/ssh"):
        if f.startswith("ssh_host_") and f.endswith(".pub"):
            path = os.path.join("/etc/ssh", f)
            try:
                result = subprocess.run(
                    ["ssh-keygen", "-lf", path],
                    capture_output=True, text=True, timeout=5, check=True,
                )
                parts = result.stdout.strip().split()
                results.append({
                    "file": f,
                    "fingerprint": parts[1] if len(parts) > 1 else result.stdout.strip(),
                    "comment": parts[2] if len(parts) > 2 else "",
                })
            except (subprocess.CalledProcessError, FileNotFoundError, OSError) as e:
                results.append({"file": f, "error": str(e)})
    return results


def get_authorized_keys() -> dict[str, list[str]]:
    result = {}
    for u in pwd.getpwall():
        if u.pw_dir and os.path.isdir(u.pw_dir):
            ak_path = os.path.join(u.pw_dir, ".ssh", "authorized_keys")
            if os.path.isfile(ak_path):
                try:
                    with open(ak_path) as f:
                        keys = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                    if keys:
                        result[u.pw_name] = keys
                except OSError:
                    pass
    return result


def main():
    audit = {
        "timestamp": int(time.time()),
        "hostname": os.uname().nodename,
        "host_keys": get_host_key_fingerprints(),
        "authorized_keys": get_authorized_keys(),
    }

    prev = {}
    try:
        with open(SSH_AUDIT_PATH) as f:
            prev = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    if prev:
        audit["changed"] = prev.get("host_keys") != audit["host_keys"] or \
            prev.get("authorized_keys") != audit["authorized_keys"]

    os.makedirs(os.path.dirname(SSH_AUDIT_PATH) or ".", exist_ok=True)
    with open(SSH_AUDIT_PATH, "w") as f:
        json.dump(audit, f, indent=2)

    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    main()
