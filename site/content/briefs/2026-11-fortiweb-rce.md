---
brief_id: brief-2026-11-01-fortiweb-rce
event_id: brief-2026-11-01-fortiweb-rce
revision: 1
activity_at: "2026-11-01T05:56:31Z"
title: 'Fortinet FortiWeb: Unauthenticated SQL injection leading to remote code execution (CVE-2025-25257)'
slug: 2026-11-fortiweb-rce
description: A critical unauthenticated SQL injection vulnerability (CVE-2025-25257) in FortiWeb allows remote code execution, with public exploit code now available.
date: "2026-11-01T05:56:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: Requires verification of patch levels in production environments
cpes:
  - cpe:2.3:a:fortinet:fortiweb:*:*:*:*:*:*:*:*
tags:
  - sqli
  - rce
  - network-appliance
vendors:
  - Fortinet
products:
  - FortiWeb (< 7.0.11)
  - FortiWeb (< 7.2.11)
  - FortiWeb (< 7.4.8)
  - FortiWeb (< 7.6.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated SQLi to RCE in FortiWeb (CVE-2025-25257)
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Unauthenticated SQLi to RCE in FortiWeb (CVE-2025-25257) via detection artifact generator.
    confidence_band: high
cves:
  - id: CVE-2025-25257
    cvss: 9.8
    epss: 0.99921
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-WATCHTOWRLABS-WATCHTOWR-VS-FORTIWEB-CVE-2025-25257
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-WATCHTOWRLABS-WATCHTOWR-VS-FORTIWEB-CVE-2025-25257&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch all FortiWeb instances to versions 7.0.11, 7.2.11, 7.4.8, 7.6.4 or above
      owner: IT Operations
      due: 24h
      evidence: Vulnerability remediation requires upgrading to the specified versions
  hunt_leads:
    - lead: Inspect web server logs for suspicious SQL injection patterns followed by outbound shell execution or connection attempts (e.g., /bin/bash)
      technique_id: T1190
      data_needed:
        - Web application access logs
        - FortiWeb diagnostic/audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Public exploit code demonstrates injection of shell commands via SQLi
  mitigation_plan:
    - priority: immediate
      action: Upgrade FortiWeb firmware
      owner: IT Operations
      addresses: CVE-2025-25257
      evidence: Vendor patch release documentation
---

Fortinet FortiWeb is affected by a critical vulnerability (CVE-2025-25257) that enables unauthenticated SQL injection, which can be leveraged to achieve remote code execution. Proof-of-concept exploitation code is publicly available, allowing for identification and potential compromise of unpatched systems. Patches are available in FortiWeb versions 7.0.11, 7.2.11, 7.4.8, and 7.6.4.

## Impact
Successful exploitation allows an unauthenticated, remote attacker to execute arbitrary code on the target appliance with full system impact (CVSS 9.8).

## Recommendation
- Upgrade all FortiWeb instances to the patched versions immediately: 7.0.11, 7.2.11, 7.4.8, or 7.6.4.
- Review network logs for requests to the FortiWeb appliance containing unusual SQL patterns or shell command sequences.
- Restrict access to the management interface of FortiWeb to known, trusted administrative IP addresses.
