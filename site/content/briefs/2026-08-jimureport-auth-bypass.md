---
title: Authentication Bypass in JimuReport
slug: 2026-08-jimureport-auth-bypass
description: JimuReport versions 2.3.4 and earlier contain an authentication bypass vulnerability allowing unauthenticated actors to enumerate reports and exfiltrate sensitive data via leaked share tokens.
date: "2026-08-17T22:51:49Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - jeecgboot
products:
  - jimureport (<= 2.3.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: JimuReport contains an authentication bypass vulnerability in the report folder template listing endpoint that allows unauthenticated attackers to enumerate all reports.
    confidence_band: high
cves:
  - id: CVE-2026-75479
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75479
  - https://github.com/jeecgboot/jimureport/issues/4695
  - https://www.vulncheck.com/advisories/jimureport-unauthenticated-report-listing-and-share-token-disclosure
rules:
  - title: Detect CVE-2026-75479 Exploitation - Unauthenticated Access to JimuReport
    description: Detects unauthenticated requests to JimuReport report template listing endpoints which are indicative of CVE-2026-75479 exploitation attempts.
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
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update JimuReport to versions beyond 2.3.4.
      owner: IT Operations
      due: 48h
      evidence: Official fix recommended for CVE-2026-75479.
  hunt_leads:
    - lead: Search for unauthenticated requests to /jimureport/template/list.
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: NVD advisory confirms vulnerability allows unauthenticated access to this endpoint.
---

JimuReport versions 2.3.4 and earlier are susceptible to an authentication bypass vulnerability located within the report folder template listing endpoint. This vulnerability enables unauthenticated remote attackers to enumerate report objects and retrieve associated share tokens. By obtaining these tokens, an attacker can bypass authorization controls on protected report endpoints to access full report definitions. This access is significant because report definitions within JimuReport often contain sensitive information, including hardcoded SQL statements, database connection logic, and live query results from connected backend data sources. The vulnerability is categorized under CWE-306 (Missing Authentication for Critical Function).

## Attack Chain

1. The attacker performs reconnaissance on the target JimuReport instance to locate the report template folder listing endpoint.
2. The attacker sends an unauthenticated HTTP request to the vulnerable endpoint.
3. The application fails to validate the user's authentication status and returns a listing of reports along with their corresponding share tokens.
4. The attacker parses the response to extract the target share tokens.
5. The attacker uses a retrieved share token to perform a subsequent request against protected report endpoints.
6. The application validates the share token as a legitimate access mechanism for the requested report.
7. The application returns the full report definition, exposing underlying database structures and query data to the attacker.

## Impact

Successful exploitation allows for the unauthorized retrieval of sensitive business intelligence, including embedded SQL statements, database schema details, and live data retrieved by the reports. This leads to information disclosure which could facilitate further attacks against backend database infrastructure. There are no currently observed victim counts, but the vulnerability affects all deployments running version 2.3.4 or earlier.

## Recommendation

* Update JimuReport to a patched version immediately as referenced in the JeecgBoot project issues.
* Audit access logs for anomalous, high-frequency requests to report template listing endpoints from unauthenticated sources.
* Monitor webserver logs for unauthorized attempts to access report endpoints using share tokens that were not previously distributed to authorized users.
