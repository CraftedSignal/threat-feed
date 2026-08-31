---
title: Authorization Bypass in Soarkey StudentManagement
slug: 2026-08-soarkey-auth-bypass
description: A vulnerability in the Administrative Servlet of Soarkey StudentManagement and 学生信息管理系统 allows remote attackers to bypass authorization via manipulation of the action argument in AdminDao.doGet.
date: "2026-08-31T07:15:39Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - vulnerability
  - authentication-bypass
vendors:
  - Soarkey
products:
  - StudentManagement (<= e08f7f1d5015af407aa4cca0ada3dea189b4937e)
  - 学生信息管理系统 (<= e08f7f1d5015af407aa4cca0ada3dea189b4937e)
cves:
  - id: CVE-2026-82621
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82621
rules:
  - title: Detect CVE-2026-82621 Exploitation Attempt - Unauthorized AdminDao Access
    description: Detects potential exploitation of CVE-2026-82621 by identifying suspicious manipulation of the 'action' parameter in requests directed at the AdminDao servlet.
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy WAF/web server rules to detect and alert on unauthorized access attempts targeting AdminDao
      owner: Detection Engineering
      due: 24h
      evidence: Source confirms public exploit availability for CVE-2026-82621
  mitigation_plan:
    - priority: immediate
      action: Restrict external network access to the administrative management interfaces
      owner: IT Operations
      addresses: CVE-2026-82621
      evidence: Vulnerability allows remote authorization bypass
---

A critical authorization bypass vulnerability has been identified in Soarkey StudentManagement and the Student Information Management System (学生信息管理系统), specifically impacting all versions up to commit e08f7f1d5015af407aa4cca0ada3dea189b4937e. The flaw is located in the AdminDao.doGet function within the Administrative Servlet component (code/src/service/AdminDao.java). An attacker can perform remote exploitation by sending a crafted HTTP request that manipulates the 'action' argument, effectively circumventing authentication and authorization controls to access restricted administrative functions. This vulnerability is particularly concerning as functional exploit code is publicly available, allowing for ease of exploitation by unauthorized actors. The vendor has been notified of the issue but has not yet provided a patch. Defenders should monitor for anomalous HTTP requests targeting administrative endpoints that utilize the 'action' parameter.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to gain unauthorized access to administrative functionality within the student management platform. This could lead to the unauthorized modification, deletion, or exfiltration of sensitive student data, potentially impacting the entire user base of the affected academic or administrative institution.

## Recommendation

- Monitor web server access logs for anomalous requests containing the 'action' parameter directed toward the AdminDao servlet, specifically looking for attempts to bypass login or gain unauthorized privileges.
- Implement strict ingress filtering for the application's administrative web interface to limit access to known, trusted IP ranges until a vendor patch is available.
- Audit existing deployments of Soarkey StudentManagement to confirm if the current version is vulnerable (up to commit e08f7f1d5015af407aa4cca0ada3dea189b4937e).
- Given the public availability of the exploit, initiate a review of logs associated with the application to identify any signs of historical unauthorized administrative access.
