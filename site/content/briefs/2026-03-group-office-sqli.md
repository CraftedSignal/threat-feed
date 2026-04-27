---
title: Group-Office JMAP Contact/Query SQL Injection Vulnerability
slug: 2026-03-group-office-sqli
description: An authenticated SQL Injection vulnerability in Group-Office's JMAP Contact/query endpoint allows data extraction, including session tokens, leading to account takeover if unpatched.
date: "2026-03-27T15:16:57Z"
severities:
  - critical
tags:
  - sqli
  - cve-2026-33755
  - group-office
  - jmap
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33755
rules:
  - title: Group-Office Suspicious JMAP Contact Query
    description: Detects suspicious POST requests to the /jmap endpoint that may indicate SQL injection attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Group-Office Potential Session Token Theft
    description: Detects potential session token theft based on unusual user agent or source IP changes.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Group-Office, an enterprise CRM and groupware tool, contains a critical SQL injection vulnerability affecting versions prior to 6.8.158, 25.0.92, and 26.0.17. The vulnerability resides in the JMAP `Contact/query` endpoint. Any authenticated user with basic address book access can exploit this flaw to extract arbitrary data from the database. A successful exploit allows an attacker to retrieve sensitive information such as active session tokens belonging to other users. This can lead to complete…
