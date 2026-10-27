---
brief_id: brief-2026-10-26-microsoft-dotnet-privilege-escalation
event_id: brief-2026-10-26-microsoft-dotnet-privilege-escalation
revision: 2
activity_at: "2026-10-27T17:08:53Z"
revision_history:
  - revision: 2
    at: "2026-10-27T17:08:53Z"
    checksum: sha256:ea35b72681e816435db9f7f6c9950cf1fca034672082681be90fda2858b3cab8
    summary: added coverage for .NET 8.x (< 8.0.33) +2 products
    changed_fields:
      - action_plan
      - affected_os
      - affected_products
      - content
      - cpes
      - cves
      - lastmod
      - references
      - severity
      - summary
      - tags
      - threat_actor
      - title
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=CA319103-2E1F-55E1-9DB2-9C3947CA217C&utm_source=rss&utm_medium=rss
title: 'Microsoft .NET: Local Privilege Escalation via SUID tarball extraction (CVE-2026-114148)'
slug: 2026-10-microsoft-dotnet-privilege-escalation
description: CVE-2026-114148 allows local privilege escalation on Linux when an administrator extracts a malicious .NET tarball containing root-owned SUID binaries.
date: "2026-10-26T19:11:52Z"
lastmod: "2026-10-27T17:08:19Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Ghost-Bx1
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Needs environment identification of affected runtimes.
cpes:
  - cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - runtime
  - linux
  - .net
  - cve-2026-114148
vendors:
  - Microsoft
products:
  - .NET
  - ASP.NET
  - .NET 8.x (< 8.0.33)
  - .NET 9.x (< 9.0.22)
  - .NET 10.x (< 10.0.14)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein lokaler Angreifer kann eine Schwachstelle in Microsoft .NET und Microsoft ASP.NET ausnutzen, um die höchsten Berechtigungen auf dem System zu erlangen.
    confidence_band: high
cves:
  - id: CVE-2026-114148
    kev_status: unknown
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4162
  - https://github.com/dotnet/core/blob/main/release-notes/8.0/8.0.33/8.0.33.md
  - https://sploitus.com/exploit?id=CA319103-2E1F-55E1-9DB2-9C3947CA217C
  - https://sploitus.com/exploit?id=CA319103-2E1F-55E1-9DB2-9C3947CA217C&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Identify and patch all .NET and ASP.NET runtimes on server and workstation fleets.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability allows local privilege escalation, requiring prompt patching to prevent host compromise.
    - action: Inventory all systems running .NET on Linux and patch to indicated versions
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-114148 remediation requirements
  hunt_leads:
    - lead: Monitor for suspicious use of local privilege escalation techniques following potential initial access.
      technique_id: T1068
      data_needed:
        - Endpoint telemetry showing unauthorized process elevation
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability specifically targets local privilege escalation.
    - lead: Search for SUID binaries within existing .NET installation directories
      technique_id: T1068
      data_needed:
        - Linux filesystem metadata
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit relies on SUID bits being set on the extracted dotnet binary
  mitigation_plan:
    - priority: immediate
      action: Apply latest Microsoft security updates for .NET and ASP.NET runtimes.
      owner: IT Operations
      addresses: Local privilege escalation vulnerability
      evidence: BSI security advisory.
    - priority: immediate
      action: Apply --no-same-owner flag to all tar extraction scripts used by root
      owner: IT Operations
      addresses: CVE-2026-114148
      evidence: Recommended mitigation from vulnerability details
updates:
  - at: "2026-10-27T17:08:19Z"
    level: L2
    summary: added coverage for .NET 8.x (< 8.0.33) +2 products
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=CA319103-2E1F-55E1-9DB2-9C3947CA217C&utm_source=rss&utm_medium=rss
---

CVE-2026-114148 is a local privilege escalation vulnerability affecting .NET Linux source-build and ASP.NET Core tarballs. The vulnerability arises because archive metadata includes root-owned (uid=0/gid=0) attributes and SUID bits on critical executables. When extracted by an administrator with root privileges, the kernel preserves these attributes. An attacker capable of substituting the legitimate tarball in locations such as package caches, CI/CD pipelines, or via unvalidated network downloads can trick an administrator into executing the tampered binary to gain root access.

## Attack Chain

1. Attacker obtains or creates a malicious version of a .NET tarball.
2. Attacker modifies the tarball contents to include a malicious executable with SUID bits (mode 4755) and root ownership (uid=0, gid=0) metadata.
3. Attacker places the malicious tarball into a target environment via an insecure cache directory, compromised internal repository, or CI/CD pipeline.
4. Administrator (or automated build process) executes the extraction command with root privileges (e.g., sudo tar -xzf).
5. The extraction process preserves the SUID and root-owner attributes of the injected binary.
6. The attacker executes the tampered binary, which triggers a privilege escalation to root.

## Impact

Successful exploitation results in full root-level compromise of the affected Linux system.

## Recommendation

- Upgrade .NET environments to the following patched versions immediately: 8.0.33, 9.0.22, or 10.0.14.
- Implement mandatory checksum verification for all downloaded .NET source-build or ASP.NET Core tarballs.
- Modify extraction procedures for root-privileged users to include the `--no-same-owner` flag: `sudo tar --no-same-owner -xzf <archive.tar.gz>`.
- Secure package cache directories and internal artifacts stores to prevent unauthorized modification.
