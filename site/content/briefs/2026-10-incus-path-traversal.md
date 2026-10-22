---
brief_id: brief-2026-10-22-incus-path-traversal
event_id: brief-2026-10-22-incus-path-traversal
revision: 2
activity_at: "2026-10-22T22:32:13Z"
revision_history:
  - revision: 2
    at: "2026-10-22T22:32:13Z"
    checksum: sha256:10d2558e7903d45b51e3c7cbec1fd1c84c9837bc128d160e7f4984935136d1aa
    summary: added coverage for Incus (6.0.3-6.0.6, 6.6.0-7.0.1, 7.1.0-7.4.x)
    changed_fields:
      - affected_products
      - lastmod
      - references
      - ttps
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-115371
title: 'Incus: Path traversal vulnerability (CVE-2026-115375)'
slug: 2026-10-incus-path-traversal
description: Incus versions 7.0.0 through 7.0.1 and 7.1.0 through 7.4.0 contain a path traversal vulnerability in instance backup processing that allows authenticated attackers to write files to the host filesystem, resulting in full host compromise.
date: "2026-10-22T20:27:23Z"
lastmod: "2026-10-22T22:30:47Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source-verified
cpes:
  - cpe:2.3:a:incus:incus:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - linux
vendors:
  - Incus
products:
  - Incus (7.0.0-7.0.1, 7.1.0-7.4.0)
  - Incus (< 6.0.7)
  - Incus (>= 6.1.0, < 7.0.2)
  - Incus (>= 7.1.0, < 7.5.0)
  - Incus (6.0.3-6.0.6, 6.6.0-7.0.1, 7.1.0-7.4.x)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can import a crafted instance backup with ../ sequences in dependent volume names to create root-owned directories with controlled content, leading to full host compromise.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Attackers can query the bucket keys endpoints to obtain S3 access and secret keys
    confidence_band: high
cves:
  - id: CVE-2026-115375
    cvss: 9.9
    kev_status: "false"
  - id: CVE-2026-115371
    kev_status: unknown
  - id: CVE-2026-115377
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115375
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115377
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115371
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade Incus to 7.0.2 or 7.5.0 or later
      owner: IT Operations
      addresses: CVE-2026-115375
      evidence: Vulnerability in Incus 7.0.0-7.0.1 and 7.1.0-7.4.0
updates:
  - at: "2026-10-22T20:27:31Z"
    level: L2
    summary: added coverage for Incus (< 6.0.7) +2 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-115377
  - at: "2026-10-22T22:30:47Z"
    level: L2
    summary: added coverage for Incus (6.0.3-6.0.6, 6.6.0-7.0.1, 7.1.0-7.4.x)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-115371
---

Incus versions 7.0.0 before 7.0.2 and 7.1.0 before 7.5.0 are affected by a path traversal vulnerability (CVE-2026-115375) in the processing of instance backup files. The vulnerability exists due to improper validation of dependent custom volume names within the index.yaml file of an instance backup. An attacker with authorization to create instances can provide a crafted backup file containing directory traversal sequences (../) in these volume names to write files to arbitrary locations on the host filesystem. Successful exploitation allows an attacker to create root-owned directories and write arbitrary content, leading to full host compromise.

## Impact

Successful exploitation allows for arbitrary file writes on the host system as root, leading to complete host compromise.

## Recommendation

- Upgrade Incus to version 7.0.2 or 7.5.0, or later, as specified in the vendor advisory.
- Audit existing instance backup archives for unauthorized modifications or unexpected path patterns in index.yaml files.
- Review permissions for users authorized to perform instance backup imports to minimize the attack surface.
