---
title: SQL Injection Vulnerability in Drogon Framework ORM Mapper
slug: 2026-09-drogon-sql-injection
description: An unauthenticated remote SQL injection vulnerability in the Drogon framework ORM Mapper allows attackers to manipulate database queries via the sort parameter.
date: "2026-09-21T06:26:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:drogonframework:drogon:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - vulnerability
  - web-application
vendors:
  - drogonframework
products:
  - drogon (<= 1.9.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack is possible to be carried out remotely.
    confidence_band: high
cves:
  - id: CVE-2026-94143
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94143
action_plan:
  priority: elevated
  owners:
    - SOC
    - Application Security
  immediate_actions:
    - action: Review codebase for usage of Mapper::orderBy in Drogon <= 1.9.13
      owner: Application Security
      due: 24h
      evidence: Source identifies Mapper::orderBy as the vulnerable function
  mitigation_plan:
    - priority: immediate
      action: Implement strict input validation on the sort parameter for all endpoints using Drogon ORM
      owner: Application Security
      addresses: CVE-2026-94143
      evidence: Vulnerability in Mapper::orderBy via sort argument manipulation
---

The Drogon framework, specifically versions up to 1.9.13, contains a critical SQL injection vulnerability in the Mapper::orderBy function located within the Mapper.h header of the ORM Mapper component. An attacker can reach this function by providing a malicious input to the 'sort' argument during an application request. Because the framework does not properly sanitize this input before including it in a database query, remote attackers can execute arbitrary SQL commands. This allows for unauthorized data exfiltration, database structure modification, or potential bypass of application authentication mechanisms. The vulnerability is publicly disclosed, and as of the latest intelligence, the vendor has not provided a patch to address this flaw. Defenders should prioritize identifying and restricting access to application endpoints that leverage the affected ORM Mapper functionality.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to execute arbitrary SQL commands against the backend database. This can lead to full database compromise, sensitive data exfiltration, and potential unauthorized administrative access to the affected web application. Given the framework is used for high-performance C++ backend services, the exposure could affect critical business logic.

## Recommendation

Prioritize code audits to identify endpoints utilizing the Mapper::orderBy function within your applications. Since no patch is available, implement application-level input validation to sanitize or block any characters or sequences indicative of SQL injection attacks in the 'sort' parameter. Deploy WAF rules to inspect HTTP parameters for common SQL injection patterns targeting the identified argument. Monitor web server logs for irregular SQL syntax within application requests.
