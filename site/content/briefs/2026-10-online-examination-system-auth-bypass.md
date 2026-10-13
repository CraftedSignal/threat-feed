---
title: Authentication Bypass in Online-Examination-System
slug: 2026-10-online-examination-system-auth-bypass
description: An authentication bypass vulnerability in the Online-Examination-System Session Handler allows remote attackers to gain unauthorized access via incorrect comparison of session cookies.
date: "2026-10-13T06:33:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:itsmeravitejak:online-examination-system:*:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - web-application-vulnerability
  - php
vendors:
  - itsmeravitejak
products:
  - Online-Examination-System (<= e6208e630b14657999bbfe4c9912302d2a1e2449)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be executed remotely.
    confidence_band: high
cves:
  - id: CVE-2026-108969
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108969
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Restrict external network access to the Online-Examination-System instance.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-108969 indicates an authentication bypass vulnerability.
  hunt_leads:
    - lead: Analyze logs for repeated access to include/session.php without associated login session creation.
      technique_id: T1190
      data_needed:
        - webserver logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability in Session::checkLogin function.
  mitigation_plan:
    - priority: immediate
      action: Monitor for patches or security updates from the itsmeravitejak project.
      owner: IT Operations
      addresses: CVE-2026-108969
      evidence: NVD vulnerability notice
---

A critical authentication vulnerability exists in the itsmeravitejak Online-Examination-System, specifically within the Session::checkLogin function located in include/session.php. The vulnerability arises from an incorrect comparison of the cookname and cookid arguments, which can be manipulated by a remote attacker to bypass authentication mechanisms. This flaw allows unauthorized access to the application without valid credentials. The issue impacts all versions up to commit e6208e630b14657999bbfe4c9912302d2a1e2449. Given that the project maintains a rolling release model and has not yet addressed the report, organizations deploying this software are at risk of remote exploitation. Defenders should monitor for anomalous authentication patterns associated with this platform.

## Attack Chain

1. Attacker performs reconnaissance to identify instances of the Online-Examination-System application.
2. Attacker inspects the session management implementation in the target environment.
3. Attacker crafts a malicious HTTP request targeting the include/session.php endpoint.
4. Attacker injects or modifies the cookname or cookid parameters within the request header or query string.
5. The server-side Session::checkLogin function fails to perform a strict comparison of the provided session parameters.
6. The authentication logic returns a successful session state despite the lack of valid credentials.
7. Attacker gains unauthorized access to the application as a registered user.
8. Attacker proceeds to perform administrative actions or exfiltrate data from the examination database.

## Impact

Successful exploitation allows for full authentication bypass, granting attackers unauthorized access to the Online-Examination-System. This could lead to the exposure of sensitive examination data, student records, and administrative controls within the application. The full scope of impact depends on the specific deployment configuration and the sensitivity of the stored information.

## Recommendation

* Monitor web application logs for unexpected access to include/session.php that does not correlate with standard login flows.
* Restrict external access to the Online-Examination-System until a patch is released by the project maintainers.
* Implement strict session validation logic at the application layer to mitigate the impact of the incorrect comparison flaw.
* Review all authentication-related code paths in custom PHP implementations that interface with the identified component.
