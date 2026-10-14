---
title: SQL Injection in sar2html
slug: 2026-10-sar2html-sqli
description: The sar2html 4.0.0 application is vulnerable to remote SQL injection via the 'sort' parameter in sar2html.py, enabling unauthenticated attackers to execute arbitrary database queries.
date: "2026-10-14T20:33:25Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:cemtan:sar2html:4.0.0:*:*:*:*:*:*:*
vendors:
  - cemtan
products:
  - sar2html (4.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack is possible to be carried out remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This manipulation of the argument sort causes sql injection.
    confidence_band: high
cves:
  - id: CVE-2026-110668
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110668
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict external network access to sar2html 4.0.0 instances
      owner: IT Operations
      due: 24h
      evidence: Public exploit availability
  hunt_leads:
    - lead: Search web logs for anomalous SQL keywords in the 'sort' parameter
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies 'sort' argument as the injection point
  mitigation_plan:
    - priority: immediate
      action: Implement WAF blocking for 'sort' parameter containing SQL syntax
      owner: SOC
      addresses: CVE-2026-110668
      evidence: Vulnerability details confirm input vector
---

The open-source monitoring tool sar2html version 4.0.0 contains a SQL injection vulnerability within the index function of the sar2html.py script. The application fails to properly sanitize the 'sort' argument provided by users, which allows an unauthenticated remote attacker to inject malicious SQL commands directly into database queries. This vulnerability is significant because a public proof-of-concept exploit is available, and the maintainers have not issued a patch to address the security flaw. Organizations currently running sar2html 4.0.0 should restrict network access to the application or implement web application firewall (WAF) rules to filter malicious payloads targeting the 'sort' parameter until a vendor-supplied update is released.

## Attack Chain

1. Attacker performs reconnaissance to identify instances of sar2html 4.0.0 exposed to the internet.
2. Attacker crafts an HTTP GET or POST request targeting the index function of sar2html.py.
3. Attacker injects malicious SQL syntax into the 'sort' parameter (e.g., payloads using 'UNION SELECT' or time-based blind SQLi).
4. The web server passes the unsanitized 'sort' parameter directly to the backend database query.
5. The database executes the injected SQL command, allowing the attacker to retrieve or modify data.
6. The application returns the results of the malicious query in the HTTP response body.
7. Attacker extracts sensitive data from the database, such as administrator credentials or system configuration.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to gain unauthorized access to the underlying database. Depending on the database configuration, this can result in the exposure of sensitive application data, credential theft, or further lateral movement within the network. As there is currently no patch, all instances of sar2html 4.0.0 are considered high-risk.

## Recommendation

* Implement WAF rules to block requests containing common SQL injection keywords (such as UNION, SELECT, OR, SLEEP, or --) within the 'sort' parameter of requests directed at sar2html.py.
* Audit access logs for suspicious HTTP requests containing special characters or SQL syntax in the 'sort' query parameter.
* Restrict network access to the sar2html application to trusted internal IP ranges only until the vendor provides a remediation.
