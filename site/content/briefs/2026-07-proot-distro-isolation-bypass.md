---
title: Proot-Distro Container Isolation Bypass via Crafted Restore Archive
slug: 2026-07-proot-distro-isolation-bypass
description: The proot-distro package fails to validate container boundaries during the restoration of archive files, allowing attackers to perform cross-container file disclosure and injection.
date: "2026-07-29T16:42:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - container-isolation
  - sandbox-escape
  - privilege-escalation
  - android
vendors:
  - Termux
products:
  - proot-distro
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The utility resolves the hardlink source from the archive's linkname field and copies the referenced file into the container identified by the archive entry.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-7h3g-4w2f-fj2f
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54727
---

The proot-distro utility, commonly used within the Termux environment on Android, contains a critical flaw in its `restore` command. The vulnerability arises from improper validation of hardlink entries within backup archives. When processing an archive, the utility resolves the `linkname` from the archive metadata to identify the source path for hardlinks. While the implementation enforces path traversal protections to ensure files remain within the general containers directory, it fails to verify that the source container specified in the hardlink matches the destination container being restored.

This logic error enables an attacker to construct a malicious tar archive that maps hardlinks to arbitrary files in any other installed container. By convincing a user to restore such an archive, an attacker can disclose sensitive data, such as SSH keys or API credentials, from a victim container or inject malicious files into a target container. The vulnerability affects proot-distro version 5.1.5 and is tracked as CVE-2026-54727.

## Attack Chain

1. Attacker creates a target victim container using `proot-distro install` to establish the filesystem structure.
2. Attacker prepares a malicious archive file using the `tarfile` Python module to define hardlink metadata.
3. Attacker sets the `linkname` attribute of the hardlink to reference sensitive files inside the victim's container path (e.g., `/root/.ssh/id_rsa`).
4. Attacker maps the source path of the hardlink to a location inside the attacker's own container or a globally readable directory.
5. Attacker lures the target user into executing `proot-distro restore` using the malicious archive.
6. The `restore` command processes the hardlink entries, resolving the cross-container reference due to lack of validation.
7. Attacker accesses the victim's sensitive data now mirrored within the attacker-controlled container filesystem.

## Impact

Successful exploitation allows for complete cross-container information disclosure and arbitrary file injection between containers on the same Android host. This impacts the confidentiality and integrity of all user-defined containers within a Termux environment. Attackers can exfiltrate SSH private keys, configuration secrets, database contents, and API credentials, or plant malicious scripts into other containers that may be executed by the victim at a later time.

## Recommendation

1. Upgrade proot-distro to the latest version once the maintainers provide a patch addressing the missing container boundary check.
2. Implement the logic provided in the brief's "Proposed Fix" to verify that the `link_container` strictly matches the `container_name` during restore operations.
3. Avoid restoring backup archives obtained from untrusted or unverified sources within the Termux environment.
4. Audit existing container configurations for any unexpected files created by previous restore operations.
