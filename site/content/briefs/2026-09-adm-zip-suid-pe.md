---
title: Local Privilege Escalation in adm-zip via Unsafe Extraction of SUID/SGID Bits
slug: 2026-09-adm-zip-suid-pe
description: The adm-zip Node.js library fails to filter SUID/SGID bits when extracting ZIP archives with 'keepOriginalPermission' enabled, allowing for root-level privilege escalation when archives are extracted by privileged processes.
date: "2026-09-29T22:18:23Z"
lastmod: "2026-10-03T00:53:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:adm-zip_project:adm-zip:*:*:*:*:*:node.js:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=23482FFE-B5C9-5736-A66B-ABBDCFF4AFA5&utm_source=rss&utm_medium=rss
tags:
  - privilege-escalation
  - nodejs
  - supply-chain
vendors:
  - cthackers
products:
  - adm-zip (<= 0.6.0)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker-crafted ZIP can produce an extracted binary with mode 04755, allowing unprivileged execution to run as root.
    confidence_band: high
cves:
  - id: CVE-2026-102282
references:
  - https://github.com/advisories/GHSA-j5f4-cc29-5x44
  - https://nvd.nist.gov/vuln/detail/CVE-2026-102282
  - https://sploitus.com/exploit?id=23482FFE-B5C9-5736-A66B-ABBDCFF4AFA5&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - Security Operations
  immediate_actions:
    - action: Audit codebase for usage of adm-zip library with keepOriginalPermission=true flag
      owner: Security Operations
      due: 48h
      evidence: Source documentation identifies this flag as the enabler of the vulnerability
  mitigation_plan:
    - priority: immediate
      action: Remove keepOriginalPermission=true from extraction logic until an updated package version is available
      owner: IT Operations
      addresses: CVE-2026-102282
      evidence: Source identifies this flag as the direct cause of the insecure permission application
updates:
  - at: "2026-10-03T00:53:58Z"
    level: L2
    summary: poc_available; added CVE-2026-102282
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=23482FFE-B5C9-5736-A66B-ABBDCFF4AFA5&utm_source=rss&utm_medium=rss
---

The adm-zip library for Node.js (version <= 0.6.0) contains a critical flaw in how it handles file permissions during archive extraction. When the `keepOriginalPermission=true` flag is used with `extractAllTo()` or `extractEntryTo()`, the library reads Unix permission bits directly from the ZIP file headers and applies them to the filesystem using `fs.chmodSync()`. Critically, the library fails to sanitize these bits, preserving the SUID (set-user-ID), SGID (set-group-ID), and sticky bits (mask 0o7777).

If an archive is processed by a privileged user (such as a root-level build pipeline, Docker build, or administrative installer), an attacker can craft a ZIP file containing an entry with SUID bits set. Upon extraction, the resulting file will be owned by root with the SUID bit enabled. If this file is later accessible and executed by a lesser-privileged user, the attacker's code will run with elevated (root) privileges. This behavior represents a form of local privilege escalation facilitated by insecure archive processing.

## Attack Chain

1. Attacker crafts a malicious ZIP archive where an entry's `external_attr` is set to include the SUID bit (e.g., `04755`).
2. The attacker delivers the archive to the target system (e.g., via upload endpoint, malicious build dependency, or project artifact).
3. The victim application or automated build system invokes `adm-zip` with `keepOriginalPermission=true` to extract the archive.
4. The extraction process, running with root privileges, calls `fs.chmodSync()` using the attacker-controlled mode bits.
5. The library writes the file to the filesystem, resulting in a root-owned file with the SUID bit set.
6. The SUID binary is moved or preserved through deployment artifacts (e.g., via `cp -a` or `rsync`).
7. An unprivileged user or service account executes the malicious binary.
8. The binary executes with root privileges, successfully achieving local privilege escalation.

## Impact

Successful exploitation leads to full local privilege escalation on systems where the library is used to handle untrusted archives under high-privilege execution contexts (e.g., root). This is particularly relevant in CI/CD pipelines and automated deployment workflows. The vulnerability is tracked as CVE-2026-102282.

## Recommendation

1. Upgrade the `adm-zip` dependency to a version where this permission bit filtering issue is remediated (note: if a patch is not yet available, avoid using the `keepOriginalPermission` flag when extracting untrusted ZIP archives).
2. Audit CI/CD pipelines and deployment scripts that use `adm-zip` to ensure that extraction does not occur under root privileges, or that source archives are verified via cryptographic signatures before extraction.
3. Use static analysis or custom instrumentation to identify code paths where `adm-zip` is invoked with `keepOriginalPermission=true` on externally sourced data.
