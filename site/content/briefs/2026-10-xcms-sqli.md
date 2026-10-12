---
title: SQL Injection in jackq XCMS Password Recovery
slug: 2026-10-xcms-sqli
description: A SQL injection vulnerability in the jackq XCMS password recovery function allows remote attackers to execute arbitrary database queries via the email parameter.
date: "2026-10-12T06:07:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jackq:xcms:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - sqli
  - remote-code-execution
vendors:
  - jackq
products:
  - XCMS (<= 3fab5342cc509945a7ce1b8ec39d19f701b89261)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-108799
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108799
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review web server access logs for anomalous characters in password reset request parameters.
      owner: SOC
      due: 24h
      evidence: The manipulation of the argument email causes sql injection.
  mitigation_plan:
    - priority: immediate
      action: Patch jackq XCMS source code to use parameterized queries in PublicController::sendFindPwdMail.
      owner: IT Operations
      addresses: CVE-2026-108799
      evidence: Impacted is the function PublicController::sendFindPwdMail of the file Admin/Home/Controller/PublicController.class.php.
---

A critical SQL injection vulnerability has been identified in jackq XCMS, affecting versions up to the commit hash 3fab5342cc509945a7ce1b8ec39d19f701b89261. The flaw resides within the PublicController::sendFindPwdMail function located in Admin/Home/Controller/PublicController.class.php. This function incorrectly handles the email argument during the password recovery process, enabling remote attackers to inject malicious SQL commands. Because this vulnerability is exposed through the password recovery endpoint, it does not require prior authentication, significantly increasing the risk of unauthorized database access, data exfiltration, or modification. An exploit has been publicly disclosed, making it highly likely that malicious actors will attempt to weaponize this endpoint in the near future.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to perform arbitrary operations on the application database. This can lead to full database compromise, unauthorized administrative access, or the theft of sensitive user information. Given that this component is a core part of the account management system, defenders should prioritize patching or restricting access to the password recovery endpoint until a fix is deployed.

## Recommendation

* Immediately audit web logs for HTTP requests directed to the password recovery endpoint containing SQL injection patterns such as OR 1=1, UNION SELECT, or stacked queries.
* Implement input validation and parameterized queries for the email parameter in the Admin/Home/Controller/PublicController.class.php component.
* Monitor web application firewall (WAF) logs for blocks related to SQL injection signatures targeting the XCMS password recovery controller.
