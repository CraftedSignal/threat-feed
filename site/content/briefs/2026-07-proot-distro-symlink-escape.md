---
title: Arbitrary Host File Write via Symlink Escape in proot-distro
slug: 2026-07-proot-distro-symlink-escape
description: The proot-distro utility contains a symlink traversal vulnerability (CVE-2026-54574) that allows malicious tar archives to overwrite arbitrary files on the host filesystem during the installation or reset process.
date: "2026-07-29T16:33:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - path-traversal
  - arbitrary-file-write
  - termux
vendors:
  - Termux
products:
  - proot-distro (5.1.4)
  - Termux app (0.119.0-beta.3)
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: An attacker can craft a malicious archive containing a symlink that points to an absolute path on the host filesystem.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Practical payloads include overwriting ~/.bashrc, ~/.profile, or $PREFIX/etc/bash.bashrc, achieving persistent code execution.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-9xq3-3fqg-4vg7
  - CVE-2026-54574
iocs:
  - type: hash_sha256
    value: 6693f415b22b2b006654da1819e08bef8bb569b9e819c62e879e79c7c060ef57
ioc_counts:
  hash_sha256: 1
---

The proot-distro utility (v5.0.2 and earlier) contains a critical path traversal vulnerability caused by insufficient validation of symlink targets during tarball extraction. When extracting a filesystem archive via the `install` or `reset` commands, the application incorrectly trusts the `linkname` property of symbolic links within the archive. An attacker can create a malicious archive containing a symlink pointing to an absolute host path, followed by a file member designed to traverse that symlink. 

Because the underlying Python `open()` call follows these links, the application writes the payload into the host filesystem with the privileges of the Termux user, bypassing the intended rootfs isolation. This allows for the overwriting of shell startup files (such as `~/.bashrc` or `~/.profile`), resulting in persistent code execution upon the next shell session. This vulnerability also impacts the `helpers/docker.py` component via the `_apply_layer` function.

## Attack Chain

1. The attacker crafts a malicious tar archive containing a symbolic link with an absolute target path (e.g., `/data/data/com.termux/files/home`).
2. The attacker includes a subsequent regular file member in the tarball that uses the symlink path as a directory prefix.
3. The victim executes `proot-distro install <malicious_archive>` or `proot-distro reset`.
4. The `_extract_plain_tar()` function in `proot_distro/commands/install.py` processes the symlink and creates it on the host filesystem without validating the target destination.
5. The extraction process reaches the regular file member and follows the attacker-controlled symlink.
6. The application writes the file content into the host filesystem location defined by the symlink.
7. The user's environment is modified, leading to persistent command execution when the user later initiates a session or modifies shell configuration.

## Impact

Successful exploitation allows for arbitrary file write on the host Android device within the Termux sandbox boundaries. By overwriting shell initialization scripts like `~/.bashrc` or `~/.profile`, attackers can achieve persistent code execution. This vulnerability affects all users of proot-distro on Termux who process untrusted or potentially compromised rootfs archives, with confirmed impact on the Termux app version 0.119.0-beta.3 and proot-distro 5.0.2.

## Recommendation

- Upgrade to a patched version of proot-distro immediately.
- Implement the `_is_safe_symlink` validation guard as described in the brief to reject symlinks with absolute targets or those that resolve outside the `rootfs_dir`.
- Audit existing tar extraction logic in other tools to ensure `member.linkname` is validated against absolute paths and directory traversal.
- Monitor for the deployment of malicious tar archives that may attempt to utilize the SHA-256 hash provided in the IOC section.
