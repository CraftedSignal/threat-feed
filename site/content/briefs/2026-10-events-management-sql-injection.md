---
title: SQL Injection Vulnerability in Events-Management-System
slug: 2026-10-events-management-sql-injection
description: An unauthenticated SQL injection vulnerability in the Registration-Edit Handler of the Events-Management-System allows remote attackers to compromise the backend database through unsanitized input parameters.
date: "2026-10-19T14:09:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:satya-vinay:events-management-system:*:*:*:*:*:*:*:*
tags:
  - sql-injection
  - web-application-vulnerability
vendors:
  - satya-vinay
products:
  - Events-Management-System (<= 437c77ceb69bf9fe2e3f4f46f7871b83f425383a)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-112141
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112141
rules:
  - title: Detect CVE-2026-112141 Exploitation - SQL Injection in doedit.php
    description: Detects attempts to exploit CVE-2026-112141 by identifying SQL injection payloads sent via POST requests to doedit.php
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
    - action: Deploy Sigma rule for doedit.php SQL injection
      owner: Detection Engineering
      due: 24h
      evidence: Vulnerability disclosure confirming RCE/SQLi potential
  mitigation_plan:
    - priority: immediate
      action: Apply WAF rules to block SQL injection payloads directed at doedit.php
      owner: IT Operations
      addresses: CVE-2026-112141
      evidence: Confirmed SQLi vulnerability in doedit.php
---

The Events-Management-System developed by satya-vinay contains a critical SQL injection vulnerability in the Registration-Edit Handler component. Specifically, the file 'doedit.php' fails to sanitize user-supplied input when passing parameters to the 'mysqli_query' function. An attacker can exploit this flaw by providing malicious input strings via the id, name, title, year, gender, fromdate, todate, or people arguments. This vulnerability permits unauthorized interaction with the underlying database, potentially leading to data exfiltration or modification. The flaw is publicly disclosed and exploitable remotely without authentication. Because the project utilizes a continuous delivery model without version tagging, all implementations up to commit hash 437c77ceb69bf9fe2e3f4f46f7871b83f425383a are considered vulnerable.

## Attack Chain

1. Attacker performs reconnaissance on the target application to identify the 'doedit.php' endpoint.
2. Attacker crafts a malicious HTTP POST request targeting the 'doedit.php' script.
3. Attacker injects SQL payloads into one or more of the parameters: id, name, title, year, gender, fromdate, todate, or people.
4. The vulnerable 'doedit.php' script receives the POST parameters without sufficient validation.
5. The application passes the unsanitized input directly into a 'mysqli_query' database function.
6. The backend database executes the injected SQL commands, allowing the attacker to bypass authentication or extract sensitive records.
7. Attacker successfully exfiltrates database contents or modifies application records to achieve unauthorized impact.

## Impact

Successful exploitation allows a remote, unauthenticated attacker to manipulate database queries, potentially leading to the exposure of sensitive user registration data, unauthorized modifications to event records, or full compromise of the application backend. As of the time of reporting, the vendor has not provided a patch for this vulnerability.

## Recommendation

- Implement input validation and sanitization for all parameters processed by 'doedit.php' to prevent SQL injection.
- Transition from raw 'mysqli_query' calls to parameterized queries (prepared statements) within the Registration-Edit Handler component.
- Monitor web application logs for HTTP POST requests to 'doedit.php' containing suspicious SQL keywords such as 'UNION', 'SELECT', 'OR 1=1', and comment delimiters (--) or (/*).
- Restrict access to the 'doedit.php' endpoint at the web application firewall or reverse proxy level until a formal security update is available from the project maintainers.
- Deploy detection rules to identify potential SQL injection attempts directed at the identified parameters within web server access logs.
