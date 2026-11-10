---
brief_id: brief-2026-11-10-nango-sql-injection
event_id: brief-2026-11-10-nango-sql-injection
revision: 1
activity_at: "2026-11-10T18:28:06Z"
title: 'Nango: Unauthenticated SQL injection in orchestrator API (CVE-2026-125759)'
slug: 2026-11-nango-sql-injection
description: Nango versions before 0.71.3 are vulnerable to an unauthenticated SQL injection allowing arbitrary query execution via the orchestrator API.
date: "2026-11-10T18:28:06Z"
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
cpes:
  - cpe:2.3:a:nango:nango:*:*:*:*:*:*:*:*
vendors:
  - Nango
products:
  - Nango (< 0.71.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Nango before 0.71.3 contains an sql injection vulnerability that allows unauthenticated attackers to execute arbitrary SQL by supplying a crafted task group key to the orchestrator API.
    confidence_band: high
cves:
  - id: CVE-2026-125759
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-125759
rules:
  - title: Detects CVE-2026-125759 Exploitation - SQL injection in /v1/immediate
    description: Detects exploitation of CVE-2026-125759 by identifying POST requests to the /v1/immediate endpoint with suspicious SQL meta-characters in the group.key parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Nango instances to version 0.71.3 or later.
      owner: IT Operations
      due: 48h
      evidence: Nango before 0.71.3 contains an sql injection vulnerability
    - action: Deploy Sigma rules and monitor for potential exploitation attempts.
      owner: SOC
      due: 24h
      evidence: Unauthenticated attackers can supply a crafted group.key parameter
  hunt_leads:
    - lead: Inspect web server logs for high volume of POST /v1/immediate requests from single IPs or presence of SQL syntax in query parameters.
      technique_id: T1190
      data_needed:
        - web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can send a malicious group.key to POST /v1/immediate
  mitigation_plan:
    - priority: immediate
      action: Upgrade Nango to 0.71.3 or later.
      owner: IT Operations
      addresses: CVE-2026-125759
      evidence: Nango before 0.71.3 contains an sql injection vulnerability
---

Nango versions prior to 0.71.3 contain an SQL injection vulnerability in the orchestrator API. An unauthenticated attacker can exploit this by submitting a crafted 'group.key' parameter to the 'POST /v1/immediate' endpoint. The 'TaskEventsHandler.notify()' function improperly interpolates this input into a PostgreSQL 'NOTIFY' statement, enabling the execution of arbitrary stacked SQL queries against the scheduler database.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary SQL commands against the Nango scheduler database, potentially leading to unauthorized data access or database modification.

## Recommendation

* Upgrade Nango to version 0.71.3 or later to remediate the vulnerability in 'TaskEventsHandler.notify()'.
* Audit logs for 'POST' requests to '/v1/immediate' where the 'group.key' parameter contains suspicious SQL characters or patterns.
