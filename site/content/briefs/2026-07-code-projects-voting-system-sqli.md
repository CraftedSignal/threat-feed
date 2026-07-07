---
title: 'CVE-2026-14648: Remote SQL Injection in code-projects Online Voting System'
slug: 2026-07-code-projects-voting-system-sqli
description: A high-severity SQL injection vulnerability, identified as CVE-2026-14648, exists in the code-projects Online Voting System up to versions 0.x/1.0, allowing remote unauthenticated attackers to bypass authentication and execute arbitrary SQL commands by manipulating `adminUserName` or `adminPassword` parameters in the `/authentication.php` login component, with public exploit details increasing the risk of active exploitation.
date: "2026-07-04T20:20:22Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - sql-injection
  - webserver
  - vulnerability
  - cve
vendors:
  - code-projects
products:
  - Online Voting System (0.x)
  - Online Voting System (1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A security vulnerability has been detected in code-projects Online Voting System... It is possible to launch the attack remotely. The exploit has been disclosed publicly and may be used.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: manipulation of the argument adminUserName/adminPassword leads to sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-14648
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14648
  - https://code-projects.org/
  - https://gist.github.com/c4ttr4ck/ed954dc2e3da968eb460a18385146f4c
  - https://vuldb.com/cve/CVE-2026-14648
  - https://vuldb.com/submit/846328
  - https://vuldb.com/vuln/376161
  - https://vuldb.com/vuln/376161/cti
rules:
  - title: Detects CVE-2026-14648 Exploitation - SQL Injection in Online Voting System Login
    description: Detects CVE-2026-14648 exploitation attempts by identifying common SQL injection metacharacters in query parameters sent to the '/authentication.php' endpoint of the code-projects Online Voting System.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A significant security vulnerability, CVE-2026-14648, has been identified in the code-projects Online Voting System, affecting all versions up to and including 0.x and 1.0. This critical flaw stems from improper input neutralization within the `test_input` function in the `/authentication.php` file, specifically impacting the login component's handling of `adminUserName` and `adminPassword` arguments. Remote attackers can leverage this SQL injection to bypass authentication and potentially manipulate the underlying database. The vulnerability has been publicly disclosed, with a CVSS v3.1 base score of 7.3 (HIGH), indicating a high potential for in-the-wild exploitation. Defenders should prioritize patching and implement robust web application security measures to mitigate the risk posed by this easily exploitable flaw.

## Attack Chain

1.  Attacker identifies an instance of the vulnerable code-projects Online Voting System accessible over the internet.
2.  The attacker crafts a malicious HTTP POST request targeting the `/authentication.php` endpoint on the exposed server.
3.  Within the POST request, the attacker embeds SQL injection payloads into the `adminUserName` or `adminPassword` parameters, such as `' OR '1'='1'--`.
4.  The vulnerable `test_input` function within `/authentication.php` processes the attacker's unsanitized input.
5.  The unsanitized input is directly concatenated into an SQL query, leading to the execution of attacker-controlled SQL commands within the application's database context.
6.  Successful SQL injection bypasses the login authentication mechanism, granting the attacker unauthorized access to the Online Voting System, potentially as an administrator.
7.  With administrative access, the attacker can then exfiltrate sensitive user data, manipulate election results, deface the application, or establish further persistence.

## Impact

Successful exploitation of CVE-2026-14648 allows remote, unauthenticated attackers to gain unauthorized administrative access to the Online Voting System. This can lead to severe consequences, including the exfiltration of sensitive voter data (e.g., personal identifiable information), manipulation of election outcomes, system defacement, or complete compromise of the underlying database. The public disclosure of the exploit significantly increases the risk of widespread attacks against unpatched systems, potentially affecting government entities, educational institutions, or any organization utilizing this voting system.

## Recommendation

*   Immediately patch the code-projects Online Voting System to a version that addresses CVE-2026-14648.
*   Deploy a Web Application Firewall (WAF) in front of internet-facing instances of the Online Voting System to filter and block malicious SQL injection attempts.
*   Enable comprehensive web server access logging and audit logs for the Online Voting System to monitor for suspicious requests to `/authentication.php` containing SQL metacharacters, correlating with the Sigma rule.
*   Deploy the provided Sigma rule to detect attempts to exploit CVE-2026-14648 in your environment.
