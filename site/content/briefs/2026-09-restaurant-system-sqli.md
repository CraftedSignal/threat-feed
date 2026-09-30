---
title: SQL Injection in AdithyaYelloju Restaurant-Management-System
slug: 2026-09-restaurant-system-sqli
description: The Restaurant-Management-System contains a remote SQL injection vulnerability in the admin/delete1.php script, allowing unauthenticated attackers to manipulate the ID parameter.
date: "2026-09-30T16:35:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:adithyayelloju:restaurant_management_system:*:*:*:*:*:*:*:*
tags:
  - web-application
  - sqli
  - vulnerability
vendors:
  - AdithyaYelloju
products:
  - Restaurant-Management-System
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
cves:
  - id: CVE-2026-103229
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103229
rules:
  - title: Detects CVE-2026-103229 Exploitation - SQL Injection in admin/delete1.php
    description: Detects potential SQL injection attempts against the Restaurant-Management-System by searching for common SQL keywords or special characters in the ID parameter of admin/delete1.php requests.
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
    - IT Operations
  immediate_actions:
    - action: Implement WAF blocking for the identified URL path and parameter pattern.
      owner: SOC
      due: 24h
      evidence: CVE-2026-103229 description of the vulnerable endpoint.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the /admin/ directory to internal IP ranges.
      owner: IT Operations
      addresses: CVE-2026-103229
      evidence: Vulnerability allows remote unauthenticated exploitation.
---

The Restaurant-Management-System project, maintained by AdithyaYelloju, contains a critical SQL injection vulnerability identified as CVE-2026-103229. The flaw resides in the 'admin/delete1.php' file, specifically within the 'mysqli_query' function used to process user input. An unauthenticated, remote attacker can execute arbitrary SQL commands by manipulating the 'ID' argument passed to this script. The project follows a continuous delivery model with rolling releases, meaning no specific version identifiers exist to distinguish vulnerable from patched code; all implementations prior to the remediation commit are considered affected. The vulnerability has been publicly disclosed and PoC exploit code is available, heightening the risk of exploitation. Defenders should inspect web server access logs for anomalous SQL syntax within requests targeting the 'admin/delete1.php' endpoint.

## Impact

Successful exploitation of this vulnerability allows unauthenticated remote attackers to execute arbitrary SQL commands against the backend database. This may lead to unauthorized data exfiltration, database structure modification, or potential credential theft from the application database. Given the nature of the application, this could result in the exposure of sensitive restaurant operations, staff data, or customer information.

## Recommendation

- Monitor web server logs for HTTP requests to 'admin/delete1.php' that contain SQL control characters or keywords (e.g., UNION, SELECT, SLEEP) in the 'ID' parameter.
- Implement a Web Application Firewall (WAF) rule to block or sanitize requests containing common SQL injection payloads targeting this specific file path.
- Review the project repository for commits addressing this issue and prioritize migrating to a version incorporating the fix, as the application does not utilize versioned releases.
- Restrict network access to the 'admin/' directory of the application to trusted administrative IP ranges only.
