---
brief_id: brief-2026-10-22-weaver-ecology-sqli
event_id: brief-2026-10-22-weaver-ecology-sqli
revision: 1
activity_at: "2026-10-22T14:16:23Z"
title: 'Weaver E-cology: Unauthenticated SQL injection (CVE-2025-71434)'
slug: 2026-10-weaver-ecology-sqli
description: Weaver E-cology versions 8.0, 9.0, and 10.0 prior to 10.76 are vulnerable to unauthenticated SQL injection, allowing attackers to exfiltrate database information via the /api/doc/out/more/list and /api/ec/dev/table/counts endpoints.
date: "2026-10-22T14:16:23Z"
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
  validation_status: Source-verified technical details
cpes:
  - cpe:2.3:a:weaver:e-cology:*:*:*:*:*:*:*:*
vendors:
  - Weaver
products:
  - E-cology (< 10.76)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Weaver E-cology 8.0, 9.0, and 10.0 prior to 10.76 contains an unauthenticated SQL injection vulnerability in the /api/doc/out/more/list endpoint.
    confidence_band: high
cves:
  - id: CVE-2025-71434
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71434
rules:
  - title: Detect CVE-2025-71434 Exploitation - SQL Injection in Weaver E-cology
    description: Detects exploitation attempts against CVE-2025-71434 by identifying malicious SQL patterns in the doc_datefrom or doc_dateto parameters of the /api/doc/out/more/list endpoint.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch Weaver E-cology to version 10.76 or later
      owner: IT Operations
      due: 24h
      evidence: Vulnerability remediation requires upgrading to version 10.76
  mitigation_plan:
    - priority: immediate
      action: Upgrade Weaver E-cology to 10.76 or later
      owner: IT Operations
      addresses: CVE-2025-71434
      evidence: NVD advisory specifies version 10.76 as fixed version
---

Weaver E-cology versions 8.0, 9.0, and 10.0 prior to 10.76 contain a critical unauthenticated SQL injection vulnerability (CVE-2025-71434). Attackers can inject malicious payloads into the doc_datefrom or doc_dateto fields within the /api/doc/out/more/list endpoint when the elementmore parameter is set to srcType=2. Extracted data can be retrieved by the attacker via the /api/ec/dev/table/counts endpoint. The Shadowserver Foundation reported observed exploitation in the wild starting on 2026-07-19.

## Impact

Successful exploitation allows unauthenticated attackers to exfiltrate sensitive data from the underlying database.

## Recommendation

* Patch Weaver E-cology to version 10.76 or later immediately.
* Monitor web server logs for HTTP requests to /api/doc/out/more/list containing suspicious characters (e.g., single quotes, SQL keywords) within the doc_datefrom or doc_dateto parameters.
* Audit access to the /api/ec/dev/table/counts endpoint for anomalous patterns suggesting unauthorized data retrieval.
