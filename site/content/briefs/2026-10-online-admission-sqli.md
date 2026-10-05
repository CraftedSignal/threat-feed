---
title: SQL Injection Vulnerability in itsourcecode Online Admission System
slug: 2026-10-online-admission-sqli
description: CVE-2026-105172 is a remote SQL injection vulnerability in itsourcecode Online Admission System 1.0, reachable via the User parameter in /login1.php, for which public exploit code is available.
date: "2026-10-05T01:43:15Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:itsourcecode:online_admission_system:*:*:*:*:*:*:*:*
tags:
  - sqli
  - web-vulnerability
vendors:
  - itsourcecode
products:
  - Online Admission System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-105172
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105172
rules:
  - title: Detect CVE-2026-105172 Exploitation - SQL Injection in /login1.php
    description: Detects attempts to exploit CVE-2026-105172 by checking for common SQL injection syntax within the 'User' parameter of /login1.php
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
    - action: Implement WAF blocking rules for /login1.php SQLi patterns
      owner: SOC
      due: 24h
      evidence: High CVSS score and public availability of exploits
  hunt_leads:
    - lead: Search web logs for 200 or 500 status codes on /login1.php with signs of SQLi in the query string
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Public exploit availability
  mitigation_plan:
    - priority: immediate
      action: Restrict access to /login1.php until the vendor issues an update
      owner: IT Operations
      addresses: CVE-2026-105172
      evidence: Vulnerability in Online Admission System 1.0
---

CVE-2026-105172 is a high-severity SQL injection vulnerability affecting version 1.0 of the itsourcecode Online Admission System. The flaw resides within the /login1.php script, specifically in the processing of the 'User' argument. An unauthenticated remote attacker can supply crafted SQL payloads within this parameter to manipulate backend database queries. This vulnerability allows for unauthorized data extraction, modification, or bypass of authentication mechanisms. Public exploit code for this vulnerability is currently available, increasing the risk of active exploitation by opportunistic actors. Organizations using this software should restrict access to the application or apply compensating controls at the web application firewall level until a patch is available.

## Attack Chain

1. Attacker performs reconnaissance to identify systems running itsourcecode Online Admission System 1.0.
2. Attacker crafts an HTTP POST or GET request targeting the /login1.php endpoint.
3. Attacker injects malicious SQL syntax into the 'User' parameter.
4. The vulnerable application passes the unsanitized 'User' input directly to the SQL query.
5. The backend database executes the injected command with application-level privileges.
6. Attacker exfiltrates sensitive database content or bypasses login controls to gain unauthorized access.

## Impact

Successful exploitation of this vulnerability can lead to complete compromise of the application database, including the theft of administrative credentials and student personal data. Given the availability of public exploits, the potential for automated exploitation is high, and organizations deploying this system are at significant risk of data exfiltration and integrity loss.

## Recommendation

1. Deploy a web application firewall (WAF) rule to block requests containing SQL injection patterns directed at /login1.php.
2. Audit web server logs for HTTP requests to /login1.php where the 'User' parameter contains SQL keywords like 'UNION', 'SELECT', or '--'.
3. Restrict external network access to the Online Admission System interface until the vendor provides a remediation or patch.
