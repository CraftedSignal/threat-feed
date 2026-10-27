---
brief_id: brief-2026-10-27-ajenti-rce
event_id: brief-2026-10-27-ajenti-rce
revision: 1
activity_at: "2026-10-27T18:00:52Z"
title: 'Ajenti: Remote code execution via improper access control (CVE-2026-27975)'
slug: 2026-10-ajenti-rce
description: Ajenti versions prior to 2.2.13 contain an improper access control vulnerability that allows an unauthenticated remote attacker to execute arbitrary code on the host server.
date: "2026-10-27T18:00:52Z"
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
  validation_status: Source verified; patch available.
cpes:
  - cpe:2.3:a:ajenti:ajenti:*:*:*:*:*:*:*:*
vendors:
  - Ajenti
products:
  - ajenti (< 2.2.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated user could gain access to a server to execute arbitrary code on this server.
    confidence_band: high
cves:
  - id: CVE-2026-27975
    cvss: 9.8
    epss: 0.00588
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-vcw3-r3fx-j444
  - https://nvd.nist.gov/vuln/detail/CVE-2026-27975
  - https://github.com/ajenti/ajenti/releases/tag/v2.2.13
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ajenti package to 2.2.13
      owner: IT Operations
      due: 24h
      evidence: This is fixed in the version 2.2.13.
  hunt_leads:
    - lead: Identify unauthorized or anonymous access attempts to the Ajenti web management interface
      technique_id: T1190
      data_needed:
        - Web server access logs (access.log)
        - Authentication logs for Ajenti service
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: An unauthenticated user could gain access to a server to execute arbitrary code.
  mitigation_plan:
    - priority: immediate
      action: Upgrade ajenti to 2.2.13
      owner: IT Operations
      addresses: CVE-2026-27975
      evidence: This is fixed in the version 2.2.13.
---

Ajenti contains a high-severity remote code execution vulnerability (CVE-2026-27975) stemming from improper access control (CWE-284). The flaw allows an unauthenticated remote attacker to gain access to the server and execute arbitrary commands. This issue is confirmed fixed in Ajenti version 2.2.13.

## Impact

Successful exploitation allows an unauthenticated attacker to achieve full remote code execution on the underlying server, resulting in potential compromise of confidentiality, integrity, and availability.

## Recommendation

- Upgrade Ajenti to version 2.2.13 or later immediately.
- Review access logs for any unauthenticated requests to the Ajenti management interface originating from unauthorized or external network segments.
