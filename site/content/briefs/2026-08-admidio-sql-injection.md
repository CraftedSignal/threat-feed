---
title: Unauthenticated Blind SQL Injection in Admidio
slug: 2026-08-admidio-sql-injection
description: Admidio versions prior to 5.0.12 contain a blind SQL injection vulnerability in the relation_type_list parameter, allowing unauthenticated attackers to exfiltrate database contents.
date: "2026-08-30T17:11:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:admidio:admidio:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sql-injection
  - cve
vendors:
  - Admidio
products:
  - Admidio (< 5.0.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Admidio before 5.0.12 contains a blind SQL injection vulnerability in the relation_type_list parameter of lists_show.php that allows unauthenticated attackers to execute arbitrary SQL queries.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Attackers can bypass authentication by providing a dummy UUID in role_list and inject SQL through relation_type_list to extract database contents including password hashes and user credentials.
    confidence_band: high
cves:
  - id: CVE-2026-82655
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82655
rules:
  - title: Detects CVE-2026-82655 Exploitation - SQL Injection in Admidio
    description: Detects exploitation attempts targeting the relation_type_list parameter in lists_show.php using common SQL injection syntax.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1505
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Admidio to 5.0.12 or later.
      owner: IT Operations
      due: 24h
      evidence: Source document indicates version 5.0.12 as the fix.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Admidio to 5.0.12
      owner: IT Operations
      addresses: CVE-2026-82655
      evidence: NVD vulnerability details.
---

Admidio versions prior to 5.0.12 contain a blind SQL injection vulnerability in the relation_type_list parameter of the lists_show.php file. This vulnerability allows unauthenticated attackers to execute arbitrary SQL queries against the underlying database. By supplying a dummy UUID in the role_list parameter, an attacker can bypass standard authentication checks and manipulate the relation_type_list parameter to perform time-based or boolean-based SQL injection. This vector provides a mechanism for unauthorized actors to exfiltrate sensitive data, including user credentials and password hashes stored in the application database.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to extract the entire contents of the Admidio database. This poses a significant risk to the confidentiality of organizational data, as the exposure of user password hashes and credentials can facilitate further unauthorized access or account takeover across the environment.

## Recommendation

- Upgrade Admidio to version 5.0.12 or later immediately to patch the vulnerable lists_show.php file.
- Review web server access logs for anomalous requests containing SQL keywords or character sequences (e.g., SLEEP, UNION, SELECT) targeting the lists_show.php endpoint.
- Implement a Web Application Firewall (WAF) rule to block or sanitize input containing common SQL injection payloads targeted at the relation_type_list parameter.
