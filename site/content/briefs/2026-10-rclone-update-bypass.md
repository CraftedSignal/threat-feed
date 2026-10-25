---
brief_id: brief-2026-10-25-rclone-update-bypass
event_id: brief-2026-10-25-rclone-update-bypass
revision: 1
activity_at: "2026-10-25T14:32:43Z"
title: 'Rclone: Self-update signature verification bypass (CVE-2026-116189)'
slug: 2026-10-rclone-update-bypass
description: Rclone versions 1.55.0 through 1.75.1 contain a signature verification bypass in the selfupdate function that allows attackers to install malicious executables by prepending unsigned checksums to the verification block.
date: "2026-10-25T14:32:43Z"
lastmod: "2026-10-25T14:32:51Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source data verified; rule creation deferred due to lack of specific process execution parameters in source.
cpes:
  - cpe:2.3:a:rclone:rclone:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - vulnerability
  - rclone
  - persistence
  - path-traversal
  - webdav
vendors:
  - rclone
products:
  - rclone (1.55.0 - 1.75.1)
  - Rclone (< 1.75.2)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1565.002
    technique_name: Transmitted Data Manipulation
    evidence: Attackers controlling the release distribution path can prepend an unsigned checksum line matching a malicious archive, causing selfupdate to install an attacker-controlled rclone executable.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Rclone before 1.75.2 contains a path traversal vulnerability in serve webdav that allows unauthenticated attackers to write above the served root.
    confidence_band: high
cves:
  - id: CVE-2026-116189
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-116191
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116189
  - https://nvd.nist.gov/vuln/detail/CVE-2026-116191
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Upgrade all instances of rclone to version 1.75.2 or later.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability addressed in rclone version 1.75.2.
    - action: Upgrade Rclone to 1.75.2 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-116191 patch availability in version 1.75.2
  hunt_leads:
    - lead: Identify systems where rclone selfupdate is actively invoked.
      technique_id: T1565.002
      data_needed:
        - Process command line arguments for rclone (looking for "selfupdate")
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability resides within the selfupdate mechanism.
    - lead: Hunt for path traversal attempts targeting WebDAV endpoints
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers can send MKCOL /.. to plant a VFS node, then PUT, MOVE, COPY, or MKCOL to create, overwrite, or delete files.
  mitigation_plan:
    - priority: immediate
      action: Update rclone to 1.75.2 or later
      owner: IT Operations
      addresses: CVE-2026-116189
      evidence: Selfupdate is the vector for the vulnerability.
    - priority: immediate
      action: Upgrade Rclone to 1.75.2 or later
      owner: IT Operations
      addresses: CVE-2026-116191
      evidence: Rclone versions prior to 1.75.2 are vulnerable
updates:
  - at: "2026-10-25T14:32:51Z"
    level: L2
    summary: added coverage for Rclone (< 1.75.2)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-116191
---

A signature verification bypass vulnerability (CVE-2026-116189) exists in the rclone 'selfupdate' mechanism. The update process fails to correctly validate the checksum block, specifically by trusting checksum lines that precede the PGP-clearsigned SHA256SUMS section. An attacker with the ability to influence the update distribution path can inject a malicious checksum, causing the rclone binary to download and execute an unauthorized, attacker-controlled file.

## Impact
Successful exploitation allows for arbitrary code execution with the privileges of the user running the rclone process. This can lead to persistent access and potential lateral movement if rclone is utilized for sensitive data synchronization or system management tasks.

## Recommendation
- Upgrade rclone to version 1.75.2 or later immediately to resolve the vulnerable verification logic in the selfupdate module.
- Review environments where rclone 'selfupdate' is enabled; consider disabling the self-update mechanism in favor of centralized package management systems (e.g., APT, YUM, Brew) to reduce the attack surface.
- Audit existing rclone installations for versions between 1.55.0 and 1.75.1.
