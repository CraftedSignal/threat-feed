---
title: Oras-Go Tar Extraction Vulnerability Allows Current Working Directory Escape (CVE-2026-50163)
slug: 2026-07-oras-go-tar-extraction-cwd-escape
description: An attacker can craft a malicious OCI artifact with a tarball layer containing a hardlink entry that uses a relative path for its target, which, when extracted by `oras-go` (<= 2.6.1) or the `oras` CLI, allows the hardlink to resolve against the process's current working directory (CWD) instead of the intended extraction base, leading to arbitrary file read or modification in the victim's CWD via an inode-sharing vulnerability.
date: "2026-07-03T12:25:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - supply-chain
  - go
  - linux
  - tar
  - hardlink
  - path-traversal
  - arbitrary-file-read
  - code-execution
vendors:
  - oras-project
products:
  - oras-go/v2 (<= 2.6.1)
  - oras CLI
affected_os:
  - Ubuntu 24.04.4 LTS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who controls an OCI-compliant registry (or any artifact source the victim consumes via `oras pull`) crafts a tarball layer...
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: 'If `oras pull` run as root (systemd without `User=`, container entrypoint default root, Kubernetes operator) --> Every file on the host filesystem: `/etc/shadow`, `/root/.ssh/id_rsa`, bind-mounted host paths, service private keys.'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564
    technique_name: Hide Artifacts
    evidence: reading one reads the other; writing to one writes to the other. This violates the 'writes inside the extract dir are confined' invariant that downstream tooling (CI systems, container-image builders, artifact scanners) typically depends on.
    confidence_band: med
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: 'Primary: arbitrary-CWD-file read primitive... Reading the extract-tree hardlink yields that file''s contents verbatim.'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: 'Secondary: inode-sharing tampering primitive. Any tool that later modifies the extract-tree hardlink (write, chmod, truncate, etc.) modifies the CWD file through the shared inode.'
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-fxhp-mv3v-67qp
iocs:
  - type: hash_sha256
    value: 040e140304b7dbdd9b40dacd798e2303cea44ad84eeb210750afdf15f1dcf8b4
  - type: url
    value: https://github.com/oras-project/oras/releases/download/v1.3.0/oras_1.3.0_linux_amd64.tar.gz
  - type: domain
    value: oras.land
ioc_counts:
  domain: 1
  hash_sha256: 1
  url: 1
---

A critical vulnerability (CVE-2026-50163) has been identified in `oras-go/v2` versions <= 2.6.1, including the `oras` CLI tool, that allows for arbitrary file reading and modification during OCI artifact extraction. An attacker can exploit this by crafting a malicious OCI artifact with a tarball layer containing a hardlink entry whose target is a relative path (e.g., `victim.secret`). When a victim uses `oras pull` or any Go application leveraging the vulnerable `oras-go/v2/content/file` package to extract this artifact, a flaw in the `ensureLinkPath` function causes the `os.Link` system call to resolve the relative hardlink target against the invoking process's current working directory (CWD) instead of the intended artifact extraction base. This enables the creation of a hardlink within the extraction directory that points to a sensitive file in the victim's CWD, allowing attackers to exfiltrate or tamper with files like `.env`, `.git/config`, or cloud credentials. The impact is elevated to critical if the `oras pull` operation is executed with root privileges, granting access to virtually any file on the host system.

## Attack Chain

1.  An attacker crafts a malicious OCI artifact layer containing a hardlink entry (`Typeflag=TypeLink`, `Linkname="victim.secret"`, where `victim.secret` is a relative path). The layer is specifically annotated for auto-extraction (`io.deis.oras.content.unpack: "true"`).
2.  The malicious artifact is published to an OCI-compliant registry controlled by the attacker or a compromised one.
3.  A victim executes `oras pull` (or any Go code using `oras-go/v2/content/file`) to retrieve the artifact, with their current working directory (CWD) containing a sensitive file named `victim.secret`.
4.  During extraction, `oras-go`'s `ensureLinkPath` function validates the hardlink. Due to a logic flaw, it incorrectly returns the original relative `Linkname` (`victim.secret`), despite internally resolving a safe absolute path for validation.
5.  The `os.Link` system call is then invoked with this relative `victim.secret` as the `oldname` parameter. Instead of resolving relative to the extraction base, `os.Link` resolves it against the process's CWD.
6.  A hardlink is created inside the victim's artifact extraction directory (e.g., `extract/payload.tar.gz/evil_cwd_link`), pointing to the sensitive `victim.secret` file located in the victim's CWD.
7.  The attacker, by subsequently accessing the extracted artifact (e.g., reading the `evil_cwd_link` file), can now read the contents of the sensitive `victim.secret` file from the victim's CWD or modify its contents through the shared inode.

## Impact

This vulnerability presents an arbitrary file read primitive, allowing an attacker to access sensitive files from the victim's current working directory (CWD). If `oras pull` is run by a regular user, files like `.env`, `.git/config`, `.aws/credentials`, SSH configurations, project-local secrets, or CI workspace files are at risk. In high-severity scenarios, such as when `oras pull` is run as root (e.g., within Kubernetes operators, systemd services without `User=` isolation, or container entrypoints), the attacker gains the ability to read or tamper with virtually any file on the host filesystem, including `/etc/shadow`, `/root/.ssh/id_rsa`, or bind-mounted host paths, making it a critical threat to CI pipelines, container orchestration, and multi-tenant environments. The PoC demonstrated successful inode sharing on Ubuntu 24.04.4 LTS, confirming the ability to access CWD files through the created hardlink.

## Recommendation

*   **Patch CVE-2026-50163 immediately:** Upgrade `oras-go/v2` to a version greater than 2.6.1. For `oras` CLI users, upgrade to the latest patched version when available.
*   **Implement `fs.protected_hardlinks`:** Ensure `fs.protected_hardlinks=1` is enabled on Linux systems. While not a full fix for user-owned files, this mitigates unauthorized hardlinking of root-owned files when the victim process runs as a regular user.
*   **Minimize `oras pull` CWD exposure:** Restrict the environment where `oras pull` or `oras-go` library calls are executed. Do not run `oras pull` from directories containing sensitive files.
*   **Limit `oras pull` privileges:** Avoid running `oras pull` as a privileged user (e.g., `root`) in production or CI/CD environments. Utilize user namespaces, unprivileged containers, or `User=` directives in systemd where applicable.
