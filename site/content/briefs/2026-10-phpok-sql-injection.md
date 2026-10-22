---
brief_id: brief-2026-10-22-phpok-sql-injection
event_id: brief-2026-10-22-phpok-sql-injection
revision: 1
activity_at: "2026-10-22T14:15:45Z"
title: 'PHPOK: Unauthenticated SQL injection in project index API (CVE-2022-51023)'
slug: 2026-10-phpok-sql-injection
description: PHPOK versions 4.5.000 through 5.4.080 contain an unauthenticated SQL injection vulnerability in the sort parameter of the project index API, enabling error-based database information extraction.
date: "2026-10-22T14:15:45Z"
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
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:phpok:phpok:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - vulnerability
  - webserver
vendors:
  - PHPOK
products:
  - PHPOK (< 5.4.081)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: PHPOK 4.5.000 before 5.4.081 contains an SQL injection vulnerability that allows unauthenticated attackers to manipulate ORDER BY clauses via the sort parameter.
    confidence_band: high
cves:
  - id: CVE-2022-51023
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-51023
rules:
  - title: Detects CVE-2022-51023 Exploitation - SQL Injection in PHPOK sort parameter
    description: Detects GET requests to the PHPOK project index API with suspicious SQL injection payloads in the sort parameter using error-based XML extraction functions.
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
    - action: Upgrade PHPOK to 5.4.081 or later
      owner: IT Operations
      due: 24h
      evidence: PHPOK 4.5.000 before 5.4.081 contains an SQL injection vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 5.4.081
      owner: IT Operations
      addresses: CVE-2022-51023
      evidence: Upgrade PHPOK to 5.4.081 or later.
---

PHPOK versions 4.5.000 through 5.4.080 contain an SQL injection vulnerability (CVE-2022-51023) in the sort parameter of the /api.php?c=project&f=index endpoint. Unauthenticated attackers can manipulate the ORDER BY clause using the extractvalue function to perform error-based data exfiltration. The Shadowserver Foundation confirmed in-the-wild exploitation of this vulnerability starting 2023-10-14.

## Impact
Successful exploitation allows unauthenticated attackers to exfiltrate information from the backend database via error messages.

## Recommendation
- Upgrade PHPOK to version 5.4.081 or later immediately.
- Monitor web access logs for GET requests to /api.php containing the sort parameter populated with SQL metacharacters or XML path expressions like extractvalue.
