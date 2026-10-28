---
brief_id: brief-2026-10-28-zabbix-sql-injection
event_id: brief-2026-10-28-zabbix-sql-injection
revision: 1
activity_at: "2026-10-28T16:04:52Z"
title: 'Zabbix: SQL injection in API sortfield parameter (CVE-2026-23921)'
slug: 2026-10-zabbix-sql-injection
description: A time-based blind SQL injection vulnerability in Zabbix API (CVE-2026-23921) allows authenticated attackers to exfiltrate database data via malicious input to the sortfield and groupBy parameters.
date: "2026-10-28T16:04:52Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:zabbix:zabbix:*:*:*:*:*:*:*:*
tags:
  - cve-2026-23921
  - sql-injection
  - zabbix
vendors:
  - Zabbix
products:
  - Zabbix (< 7.0.22)
  - Zabbix (< 7.2.15)
  - Zabbix (< 7.4.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Blind SQL injection via the sortfield parameter in the Zabbix API
    confidence_band: high
cves:
  - id: CVE-2026-23921
    cvss: 8.8
    epss: 0.04098
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-QUCKLECRABIK-CVE-2026-23921
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-QUCKLECRABIK-CVE-2026-23921&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2026-23921 Exploitation - SQL Injection via Zabbix API
    description: Detects attempts to exploit CVE-2026-23921 by identifying unusual characters in Zabbix API sortfield or groupBy parameters.
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
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch all Zabbix instances to version 7.0.22, 7.2.15, 7.4.6, or higher.
      owner: IT Operations
      due: 48h
      evidence: Upgrade Zabbix to 7.0.22 / 7.2.15 / 7.4.6 or later.
  hunt_leads:
    - lead: Review Zabbix access logs for API calls containing SQL injection strings in parameters
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Blind SQL injection via the sortfield parameter in the Zabbix API
  mitigation_plan:
    - priority: immediate
      action: Upgrade Zabbix to 7.0.22 or later
      owner: IT Operations
      addresses: CVE-2026-23921
      evidence: CVE-2026-23921 is a time-based blind SQL injection vulnerability in Zabbix
---

CVE-2026-23921 is a time-based blind SQL injection vulnerability in the Zabbix API. The flaw exists in `CApiService::applyQuerySortOptions()` where a failure to properly validate the `sortfield` parameter when combined with a user-supplied `groupBy` array allows for SQL injection. Attackers can provide a malicious payload that reaches the `ORDER BY` clause of SQL queries without sanitization. The vulnerability affects Zabbix versions prior to 7.0.22, 7.2.15, and 7.4.6. Public exploit code is available.

## Attack Chain

1. Attacker authenticates to the Zabbix API using a valid user account.
2. Attacker invokes an API method such as `host.get`, `trigger.get`, or `item.get`.
3. Attacker injects a payload into the `groupBy` parameter and the `sortfield` parameter.
4. The `zbx_array_merge()` function merges the attacker-controlled `groupBy` into the options array.
5. `CApiService::applyQuerySortOptions()` validates the `sortfield` using the attacker-controlled `groupBy` input, effectively bypassing the whitelist.
6. The `createSelectQueryFromParts()` function generates the final SQL query containing the unsanitized `ORDER BY` clause.
7. The database executes the injected SQL, allowing for time-based data exfiltration via `pg_sleep()` or equivalent functions.

## Impact

Successful exploitation allows for blind, time-based data exfiltration from the underlying database (PostgreSQL or MySQL). An attacker must have valid API credentials to reach the vulnerable code path.

## Recommendation

- Upgrade Zabbix immediately to version 7.0.22, 7.2.15, 7.4.6, or higher to receive the patch that replaces `array_merge` with `array_intersect` for input validation.
- Audit Zabbix API access logs for anomalous `sortfield` or `groupBy` usage patterns.
- Restrict access to the Zabbix API to authorized IP addresses or internal networks.
