---
title: PraisonAI Symlink Extraction Bypass Vulnerability
slug: 2026-05-praisonai-symlink-bypass
description: PraisonAI versions 2.7.2 through 4.6.35 are vulnerable to an arbitrary file write due to improper validation of symlinks during archive extraction, affecting `recipe pull`, `recipe publish`, and `recipe unpack` flows.
date: "2026-05-11T14:01:45Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:praison:praisonai:*:*:*:*:*:*:*:*
tags:
  - symlink
  - arbitrary file write
  - path traversal
  - attack.persistence
  - attack.privilege_escalation
vendors:
  - PraisonAI
products:
  - PraisonAI
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1553
    technique_name: Subvert Trust Relationships
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1553
    technique_name: Subvert Trust Relationships
cves:
  - id: CVE-2026-44340
    cvss: 7.5
    epss: 0.00017
references:
  - https://github.com/advisories/GHSA-9q28-ghcr-c4x3
  - https://github.com/MervinPraison/PraisonAI/security/advisories/new
rules:
  - title: Detect PraisonAI Symlink Extraction Bypass
    description: Detects CVE-2026-44340 exploitation — PraisonAI archive extraction creating symlinks with external targets
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1553.005
    data_sources:
      - process_creation
      - linux
  - title: Detect PraisonAI Unpack Command with Malicious Archive
    description: Detects PraisonAI unpack command execution with archive files that contain directory traversal sequences.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI versions 2.7.2 through 4.6.35 are susceptible to a symlink extraction bypass vulnerability. The vulnerability exists within the `_safe_extractall` helper function, which is used by `recipe pull`, `recipe publish`, and `recipe unpack` functionalities. The core issue lies in the lack of validation for `member.linkname` and the failure to reject symlink members during archive extraction. This allows a malicious actor to craft a `.praison` bundle containing a symlink that points outside the intended destination directory, leading to arbitrary file writes. This vulnerability re-opens attack vectors that previous patches (GHSA-99g3-w8gr-x37c, GHSA-4rx4-4r3x-6534, GHSA-r9x3-wx45-2v7f, and GHSA-4ph2-f6pf-79wv) aimed to mitigate.

## Attack Chain

1. An attacker crafts a malicious `.praison` bundle containing a symlink member.
2. The symlink's `name` is within the intended destination directory.
3. The symlink's `linkname` points to a location outside the destination directory (e.g., `/tmp/PWNED`).
4. The malicious bundle also includes a regular file member.
5. The regular file's path traverses through the previously created symlink (e.g., `legit/escape/owned.txt`).
6. A user or server processes the malicious `.praison` bundle using `praisonai recipe unpack`, `praisonai recipe pull`, or a registry archive validation process.
7. During extraction, the symlink is created first, pointing to the attacker-controlled location.
8. When the regular file is extracted, it follows the symlink, resulting in an arbitrary file write to the attacker's chosen location.

## Impact

Successful exploitation allows an attacker to write arbitrary files with attacker-controlled content to any location on the filesystem accessible to the PraisonAI process. This can lead to various outcomes, including: overwriting user configuration files (`.bashrc`, `.zshrc`, `.profile`, SSH `authorized_keys`, cron entries), modifying project files, or, if the process runs as root, compromising the entire system. This vulnerability impacts all hosts processing malicious `.praison` bundles through affected `praisonai` versions.

## Recommendation

*   Upgrade to a patched version of PraisonAI that includes the `filter="data"` argument in the `tar.extractall` call to prevent symlink extraction bypass (`recipe/registry.py:178`).
*   For older Python versions, implement an explicit check for symlinks and hardlinks during archive extraction, validating that the link target remains within the intended destination directory as described in the suggested remediation.
*   Deploy the Sigma rule "Detect PraisonAI Symlink Extraction Bypass" to identify potential exploitation attempts by monitoring for archive extractions containing suspicious symlinks.
