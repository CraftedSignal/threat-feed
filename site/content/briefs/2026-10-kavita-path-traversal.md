---
brief_id: brief-2026-10-22-kavita-path-traversal
event_id: brief-2026-10-22-kavita-path-traversal
revision: 1
activity_at: "2026-10-22T14:15:54Z"
title: 'Kavita: Path traversal vulnerability (CVE-2022-51024)'
slug: 2026-10-kavita-path-traversal
description: Kavita versions 0.5.2 through 0.5.4.0 contain a path traversal vulnerability in the /api/image/cover-upload endpoint, allowing unauthenticated attackers to read arbitrary files.
date: "2026-10-22T14:15:54Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:kavitareader:kavita:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - path-traversal
  - cve-2022-51024
vendors:
  - Kavita
products:
  - Kavita (0.5.2 <= version < 0.5.4.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Kavita 0.5.2 before 0.5.4.1 contains a path traversal vulnerability that allows unauthenticated attackers to read arbitrary files.
    confidence_band: high
cves:
  - id: CVE-2022-51024
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-51024
rules:
  - title: Detect CVE-2022-51024 Exploitation - Path Traversal
    description: Detects exploitation attempts against CVE-2022-51024 where the filename parameter contains traversal sequences
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Kavita to 0.5.4.1 or later
      owner: IT Operations
      due: 24h
      evidence: Vulnerability disclosure requires version upgrade
    - action: Hunt for historical exploitation attempts in web logs
      owner: SOC
      due: 48h
      evidence: Shadowserver observed in-the-wild exploitation since 2023-10-18
  mitigation_plan:
    - priority: immediate
      action: Upgrade Kavita to 0.5.4.1
      owner: IT Operations
      addresses: CVE-2022-51024
      evidence: NVD advisory
---

Kavita versions prior to 0.5.4.1 are susceptible to a path traversal vulnerability. Unauthenticated attackers can exploit the 'filename' parameter within the '/api/image/cover-upload' endpoint to access files outside of the intended directory by injecting directory traversal sequences (e.g., '../'). The Shadowserver Foundation observed in-the-wild exploitation of this vulnerability beginning on 2023-10-18.

## Impact
Successful exploitation allows unauthenticated attackers to read arbitrary files from the server's filesystem, including sensitive configuration files such as 'appsettings.json'.

## Recommendation
- Update Kavita to version 0.5.4.1 or later immediately.
- Audit server access logs for requests to '/api/image/cover-upload' containing directory traversal sequences ('../').
- Restrict network access to the Kavita management interface to trusted subnets.
