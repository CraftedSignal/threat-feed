---
brief_id: brief-2026-10-22-incus-restriction-bypass
event_id: brief-2026-10-22-incus-restriction-bypass
revision: 1
activity_at: "2026-10-22T20:28:33Z"
title: 'Incus: Project restriction bypass and privilege escalation (CVE-2026-115372)'
slug: 2026-10-incus-restriction-bypass
description: A project restriction bypass in Incus 7.3.0 through 7.4.x allows restricted users to inject malicious arguments into the mkfs command, leading to privilege escalation on the host.
date: "2026-10-22T20:28:33Z"
lastmod: "2026-10-22T20:28:41Z"
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
  validation_status: Source verified; no IOCs or specific log behavior documented.
cpes:
  - cpe:2.3:a:linuxcontainers:incus:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - s3
  - incus
vendors:
  - Linux Containers
products:
  - Incus (7.3.0 - 7.4.x)
  - Incus (7.0.0-7.0.1, 7.1.0-7.4.x)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can set the option on a custom volume and trigger a copy or move onto a formatting pool to inject arguments into mkfs executed as root.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Incus versions 7.0.0 through 7.0.1 and 7.1.0 through 7.4.x contain a signature verification flaw in the built-in S3 server.
    confidence_band: high
cves:
  - id: CVE-2026-115372
    cvss: 8.5
    kev_status: "false"
  - id: CVE-2026-115374
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115372
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115374
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Incus instances to version 7.5.0 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability remediation requires upgrading to the patched version.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Incus to 7.5.0
      owner: IT Operations
      addresses: CVE-2026-115372
      evidence: Fixed in 7.5.0
updates:
  - at: "2026-10-22T20:28:41Z"
    level: L2
    summary: added coverage for Incus (7.0.0-7.0.1, 7.1.0-7.4.x)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-115374
---

Incus versions 7.3.0 through 7.4.x (prior to 7.5.0) contain a project restriction bypass. The vulnerability allows users within a restricted project to set the 'block.create_options' property during volume update, copy, or move operations. An attacker can leverage this to inject arbitrary arguments into the 'mkfs' command, which is executed with root privileges by the Incus daemon on the host.

## Impact

Successful exploitation allows a restricted project user to achieve command execution with root privileges on the underlying host system.

## Recommendation

Upgrade Incus to version 7.5.0 or later immediately to remediate the vulnerability. If an upgrade is not immediately feasible, restrict the ability of untrusted users to perform volume update, copy, or move operations within projects where project restrictions are relied upon for security isolation.
