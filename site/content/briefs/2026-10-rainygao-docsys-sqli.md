---
title: SQL Injection in RainyGao DocSys
slug: 2026-10-rainygao-docsys-sqli
description: RainyGao DocSys versions up to 2.02.85 contain a remote SQL injection vulnerability in the Database Management component, allowing unauthenticated attackers to execute arbitrary SQL commands via the url argument.
date: "2026-10-04T16:53:43Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rainygao:docsys:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - sqli
  - vulnerability-management
vendors:
  - RainyGao
products:
  - DocSys (<= 2.02.85)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-105158
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105158
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external network access to DocSys Database Management endpoints
      owner: IT Operations
      due: 24h
      evidence: Unauthenticated remote access is possible
  mitigation_plan:
    - priority: immediate
      action: Implement WAF rules to block SQL injection payloads targeting the url argument
      owner: SOC
      addresses: CVE-2026-105158
      evidence: SQL injection vulnerability in url parameter
---

RainyGao DocSys versions up to 2.02.85 contain a critical SQL injection vulnerability (CVE-2026-105158) located within the Database Management component. The flaw exists in the BaseController.createDBForMysql function within the BaseController.java file. An unauthenticated remote attacker can exploit this vulnerability by manipulating the 'url' argument passed to the function. Successful exploitation allows for the execution of arbitrary SQL commands against the backend database, potentially leading to unauthorized data access, modification, or deletion. The vulnerability has been publicly disclosed and a proof-of-concept exploit may be available. As of the time of reporting, the vendor has not provided a patch for this issue.

## Impact

The vulnerability allows unauthenticated remote attackers to perform SQL injection attacks, which could result in full database compromise. Depending on the database configuration, this may lead to complete data exfiltration, unauthorized administrative access, or loss of system integrity.

## Recommendation

* Monitor web server logs for HTTP requests directed at the Database Management component that contain common SQL injection patterns in the 'url' argument.
* Implement strict input validation and parameterization for all user-supplied data, particularly the 'url' parameter within the Database Management module, to mitigate the risk until an official patch is released by the vendor.
* Restrict network access to the DocSys administration and management interfaces to trusted IP addresses only, reducing the attack surface for remote exploitation.
