---
brief_id: brief-2026-10-20-foosun-dotnetcms-sqli
event_id: brief-2026-10-20-foosun-dotnetcms-sqli
revision: 1
activity_at: "2026-10-20T21:53:35Z"
title: FooSun DotNetCMS SQL Injection (CVE-2015-20128)
slug: 2026-10-foosun-dotnetcms-sqli
description: FooSun DotNetCMS versions 1.0 and 2.0 contain an unauthenticated SQL injection vulnerability in the CityId parameter of the /user/City_ajax.aspx endpoint, which is being actively exploited to extract database information.
date: "2026-10-20T21:53:35Z"
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
  - cpe:2.3:a:foosun:dotnetcms:*:*:*:*:*:*:*:*
tags:
  - sqli
  - web-vulnerability
  - dotnetcms
vendors:
  - FooSun
products:
  - DotNetCMS (1.0, 2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: FooSun DotNetCMS 1.0 and 2.0 contains an SQL injection vulnerability that allows unauthenticated attackers to manipulate MSSQL queries through the CityId parameter.
    confidence_band: high
cves:
  - id: CVE-2015-20128
    cvss: 8.2
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2015-20128
rules:
  - title: Detect CVE-2015-20128 Exploitation - SQL Injection in DotNetCMS
    description: Detects exploitation attempts against CVE-2015-20128 by monitoring for SQL keywords in the CityId parameter of the /user/City_ajax.aspx endpoint.
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to identify exploitation attempts for CVE-2015-20128
      owner: Detection Engineering
      due: 24h
      evidence: Vulnerability is actively exploited in the wild.
  hunt_leads:
    - lead: Inspect web logs for anomalous GET requests to /user/City_ajax.aspx
      technique_id: T1190
      data_needed:
        - webserver logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows unauthenticated attackers to extract database information.
---

FooSun DotNetCMS versions 1.0 and 2.0 are susceptible to an unauthenticated SQL injection vulnerability identified as CVE-2015-20128. The flaw exists within the processing of the CityId parameter on the /user/City_ajax.aspx endpoint. Attackers can inject malicious SQL commands, specifically using UNION SELECT payloads, which are concatenated into the back-end MSSQL query without proper sanitization. This vulnerability allows remote, unauthenticated actors to extract sensitive data from the underlying database. The vulnerability has been documented as being actively exploited in the wild since October 2023. Given the lack of input validation, defenders should monitor for anomalous HTTP requests targeting this specific endpoint.

## Attack Chain

1. Attacker performs reconnaissance to identify exposed instances of FooSun DotNetCMS.
2. Attacker crafts an HTTP GET request targeting the /user/City_ajax.aspx endpoint.
3. Attacker injects a malicious payload into the CityId parameter (e.g., using UNION SELECT syntax).
4. The DotNetCMS application receives the request and fails to sanitize the CityId input.
5. The application concatenates the malicious input directly into an MSSQL query for the sys_City database operation.
6. The back-end database executes the injected query, returning sensitive database content to the application.
7. The application returns the exfiltrated database results within the HTTP response to the attacker.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to perform arbitrary SQL queries against the underlying database. This leads to the potential exfiltration of sensitive information, including user credentials, configuration data, or other proprietary content stored within the DotNetCMS database, posing a high risk to data confidentiality.

## Recommendation

* Deploy the provided Sigma rule to your web application firewall or SIEM to detect exploitation attempts targeting /user/City_ajax.aspx.
* Audit logs for suspicious GET requests to /user/City_ajax.aspx containing SQL injection syntax, particularly UNION and SELECT keywords in the CityId parameter.
* Review database access logs and application error logs for signs of unauthorized data retrieval or unexpected SQL syntax errors.
* If possible, upgrade to a non-vulnerable version of the CMS or apply a vendor-provided patch to remediate CVE-2015-20128.
