---
title: 'mailcow: dockerized Second-Order SQL Injection Vulnerability (CVE-2026-40871)'
slug: 2024-01-02-mailcow-sql-injection
description: 'A second-order SQL injection vulnerability (CVE-2026-40871) exists in mailcow: dockerized versions prior to 2026-03b due to improper validation of the quarantine_category field in the /api/v1/add/mailbox endpoint, leading to potential exfiltration of sensitive data.'
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - mailcow
  - cve-2026-40871
  - webserver
vendors:
  - mailcow
products:
  - 'mailcow: dockerized'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40871
    cvss: 7.2
    epss: 0.09874
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40871
rules:
  - title: Detect Mailcow Unsafe Quarantine Category Update
    description: Detects suspicious API requests to /api/v1/add/mailbox with potential SQL injection in the quarantine_category parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Mailcow Quarantine Notify SQL Injection via Audit Logs
    description: Detects SQL injection attempts by monitoring application audit logs for suspicious patterns originating from quarantine_notify.py interacting with the database.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1213
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Mailcow: dockerized, an open-source groupware/email suite based on Docker, is vulnerable to a second-order SQL injection (CVE-2026-40871) in versions prior to 2026-03b. The vulnerability lies in the `/api/v1/add/mailbox` endpoint, which stores the `quarantine_category` field without proper validation or sanitization. This unsanitized value is subsequently used by the `quarantine_notify.py` script when constructing SQL queries. The script employs unsafe string formatting (`%`) instead of parameterized queries, which enables an attacker to inject arbitrary SQL code. This SQL injection is triggered when the quarantine notification job executes. This allows attackers to exfiltrate sensitive data. The vulnerability is fixed in version 2026-03b.

## Attack Chain

1. An attacker crafts a malicious API request to the `/api/v1/add/mailbox` endpoint.
2. The malicious request includes a crafted `quarantine_category` value containing SQL injection payloads.
3. The mailcow application stores the unsanitized `quarantine_category` value in the database.
4. The `quarantine_notify.py` script is executed as part of the quarantine notification job.
5. `quarantine_notify.py` constructs a SQL query using the stored, malicious `quarantine_category` value and unsafe string formatting.
6. The injected SQL code is executed against the database, allowing the attacker to perform arbitrary SQL operations.
7. The attacker uses `UNION SELECT` statements to extract sensitive data, such as admin credentials.
8. The extracted data is included in quarantine notification emails, potentially exposing it to the attacker or other unintended recipients.

## Impact

Successful exploitation of this vulnerability allows attackers to inject arbitrary SQL commands into the mailcow: dockerized database. This could lead to the exfiltration of sensitive information, such as admin credentials, API keys, or user data. The exfiltrated data can then be used for further malicious activities, including account takeover, data breaches, or privilege escalation. Although the exact number of potential victims is unknown, any mailcow: dockerized instance running a version prior to 2026-03b is susceptible.

## Recommendation

*   Upgrade mailcow: dockerized to version 2026-03b or later to patch CVE-2026-40871.
*   Implement input validation and sanitization for the `quarantine_category` field in the `/api/v1/add/mailbox` endpoint to prevent SQL injection attacks.
*   Deploy the Sigma rule `Detect Mailcow Unsafe Quarantine Category Update` to detect suspicious API requests containing potential SQL injection payloads targeting the `/api/v1/add/mailbox` endpoint.
*   Review and update the `quarantine_notify.py` script to use parameterized queries instead of unsafe string formatting to prevent SQL injection vulnerabilities.
