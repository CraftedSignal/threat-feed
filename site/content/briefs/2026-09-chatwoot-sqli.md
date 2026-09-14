---
title: SQL Injection in Chatwoot FilterService
slug: 2026-09-chatwoot-sqli
description: An authenticated SQL injection vulnerability (CVE-2026-44706) in Chatwoot versions 4.11.1 and earlier allows attackers to perform unauthorized database queries and exfiltrate sensitive data.
date: "2026-09-14T06:12:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:chatwoot:chatwoot:*:*:*:*:*:*:*:*
vendors:
  - Chatwoot
products:
  - Chatwoot (<= 4.11.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SQL injection in Chatwoot <= 4.11.1 FilterService lets agents read full PostgreSQL database.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: An authenticated attacker can perform arbitrary SQL queries against the underlying PostgreSQL database, potentially leading to the theft of user credentials and API tokens.
    confidence_band: high
cves:
  - id: CVE-2026-44706
    cvss: 8.5
    epss: 0.00227
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HAKAIOFFSEC-CVE-2026-44706
rules:
  - title: Detects CVE-2026-44706 Exploitation - SQL Injection via Chatwoot API
    description: Detects exploitation of CVE-2026-44706 by monitoring for common SQL injection patterns in requests to the conversation filter endpoint
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
    - action: Upgrade Chatwoot to 4.11.2 or later
      owner: IT Operations
      due: 48h
      evidence: Source states Chatwoot <= 4.11.1 is vulnerable
  hunt_leads:
    - lead: Search logs for POST requests to conversation filter API containing SQL keywords
      technique_id: T1190
      data_needed:
        - Web application request logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploit targets conversation filter endpoint via SQL injection
  mitigation_plan:
    - priority: immediate
      action: Update Chatwoot to 4.11.2 or later
      owner: IT Operations
      addresses: CVE-2026-44706
      evidence: Source identifies vulnerability in versions <= 4.11.1
---

Chatwoot versions 4.11.1 and earlier contain a critical SQL injection vulnerability in the FilterService, identified as CVE-2026-44706. The vulnerability resides in the `FilterService#lt_gt_filter_values` method, which fails to properly parameterize values within the `is_greater_than` operator used during conversation filtering. An authenticated attacker, such as a malicious or compromised agent, can send specially crafted requests to the `/api/v1/accounts/{account_id}/conversations/filter` endpoint to execute arbitrary SQL commands against the underlying PostgreSQL database. This allows for the exfiltration of sensitive information, including user credentials and API tokens. The availability of public proof-of-concept exploit code increases the risk of successful exploitation in enterprise environments.

## Attack Chain

1. Attacker obtains valid authentication credentials for a low-privileged agent account in the target Chatwoot instance.
2. Attacker interacts with the `/api/v1/accounts/{account_id}/conversations/filter` API endpoint.
3. Attacker injects malicious SQL payloads into the request body, specifically targeting the `is_greater_than` operator parameters.
4. The vulnerable `FilterService` component processes the unparameterized input, executing the malicious SQL query on the PostgreSQL database.
5. Attacker employs boolean-based or time-based blind SQL injection techniques to infer database structure and content.
6. Attacker exfiltrates sensitive rows, specifically targeting user account tables, credentials, and API tokens.
7. Final objective is achieved: unauthorized access to administrative credentials and internal platform data.

## Impact

Successful exploitation of this vulnerability allows an authenticated agent to bypass standard authorization controls and dump the entire PostgreSQL database. This results in the exposure of highly sensitive data, including customer PII, internal communication logs, and administrative API tokens, which could be leveraged for lateral movement or full platform takeover.

## Recommendation

1. Upgrade all Chatwoot instances to a version later than 4.11.1 immediately.
2. Implement strict monitoring on the `/api/v1/accounts/{account_id}/conversations/filter` endpoint for anomalous HTTP request bodies containing SQL syntax characters (e.g., `'`, `--`, `UNION`, `SELECT`).
3. Review access logs for excessive or unusual activity originating from low-privileged agent accounts.
4. Perform a security audit of current agent permissions to ensure the principle of least privilege is enforced within the Chatwoot dashboard.
