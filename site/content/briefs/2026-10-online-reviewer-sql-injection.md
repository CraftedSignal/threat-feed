---
title: SQL Injection in code-projects Online Reviewer System
slug: 2026-10-online-reviewer-sql-injection
description: The code-projects Online Reviewer System 1.0 contains a remote SQL injection vulnerability in the User Update Handler, with a public exploit currently available.
date: "2026-10-13T02:31:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:code-projects:online_reviewer_system:1.0:*:*:*:*:*:*:*
tags:
  - web-application
  - sqli
  - sql-injection
  - vulnerability
vendors:
  - code-projects
products:
  - Online Reviewer System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108956
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external network access to the Online Reviewer System deployment
      owner: IT Operations
      due: 24h
      evidence: High severity SQL injection vulnerability with public exploit
  mitigation_plan:
    - priority: immediate
      action: Remove or patch the affected component '/reviewer/system/system/admins/manage/users/btn_functions.php'
      owner: IT Operations
      addresses: CVE-2026-108956
      evidence: NVD vulnerability details
---

A SQL injection vulnerability has been identified in the Online Reviewer System version 1.0, developed by code-projects. The flaw exists within the User Update Handler component, specifically in the file '/reviewer/system/system/admins/manage/users/btn_functions.php'. An unauthenticated remote attacker can leverage this vulnerability to manipulate backend database queries through an unknown parameter or function. This allows for unauthorized access to, or modification of, sensitive application data. The vulnerability is considered high-risk due to the existence of publicly available exploit code, increasing the likelihood of opportunistic exploitation against deployments of this software.

## Impact

Successful exploitation allows remote attackers to bypass security controls to access or modify the application database. This could result in the exfiltration of user records, administrative account takeover, or the deletion of critical data. Organizations using this software are at significant risk of data compromise if the application remains exposed to the internet.

## Recommendation

* Immediately restrict public access to the Online Reviewer System application.
* Audit web server logs for suspicious POST or GET requests targeting '/reviewer/system/system/admins/manage/users/btn_functions.php' containing SQL keywords such as 'UNION', 'SELECT', 'OR 1=1', or comment characters like '--'.
* Given the lack of a vendor patch, evaluate replacing the vulnerable application with a supported alternative.
