---
title: SQL Injection in Pimcore via ClassDefinition UID
slug: 2026-08-pimcore-sql-injection
description: An improper input validation in Pimcore's ClassDefinition UID and unsanitized SQL query construction allow authenticated users to perform UNION-based SQL injection and exfiltrate database contents.
date: "2026-08-13T14:21:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - sqli
  - pimcore
vendors:
  - Pimcore
products:
  - Pimcore
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability allows an authenticated user to perform UNION-based SQL injection via the ClassDefinition UID.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2mhj-fhvg-v428
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55072
rules:
  - title: Detects CVE-2026-55072 Exploitation - SQL Injection via ClassDefinition UID
    description: Detects attempts to create a ClassDefinition with a UID containing SQL injection syntax, identifying potential exploitation of the missing regex anchor vulnerability.
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
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Pimcore to version 12.3.9 or higher.
      owner: IT Operations
      due: 24h
      evidence: Source advisory recommends upgrading to patched version.
  hunt_leads:
    - lead: Search logs for POST requests to /api/class/definition/ containing SQL keywords.
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit PoC uses this specific endpoint.
  mitigation_plan:
    - priority: immediate
      action: Review all ClassDefinitions for anomalous UIDs.
      owner: IT Operations
      addresses: CVE-2026-55072
      evidence: Attack utilizes malicious UIDs to trigger SQLi.
---

Pimcore versions 2026.1.0 through 2026.1.4 and versions prior to 12.3.9 are vulnerable to SQL injection (CVE-2026-55072). The vulnerability stems from an incomplete fix regarding input validation of ClassDefinition UIDs. The regex used to validate the UID lacks an end anchor (`$`), allowing a user with 'objects' permissions to supply a string that starts with a valid character but contains additional malicious SQL. 

When this class is subsequently instantiated and accessed via a 'Block' field, the `Block.php` component concatenates the raw, unquoted classId directly into SQL queries. This allows an attacker to break out of the intended query context and execute arbitrary SQL commands. An attacker can leverage this to exfiltrate sensitive data, including password hashes from the `users` table, by performing a UNION-based SQL injection attack.

## Attack Chain

1. Attacker authenticates to the Pimcore Studio API with valid 'objects' level credentials.
2. Attacker invokes the `create` action on the `ClassDefinition` configuration endpoint.
3. Attacker submits a specially crafted `uid` parameter containing a SQL payload (e.g., `1 UNION SELECT...`).
4. The application processes the `uid` using an insufficiently anchored regex, which passes validation.
5. The attacker creates a new data object associated with this malicious class definition.
6. Attacker requests the data object via the API, triggering `Block.php` to load field data.
7. `Block.php` performs an unquoted string concatenation of the classId into a database query.
8. The underlying database executes the injected payload, returning sensitive table contents in the API response.

## Impact

Successful exploitation allows an authenticated editor-level user to perform arbitrary SQL queries against the application database. This enables unauthorized exfiltration of sensitive information, including user credentials and configuration data. The impact is significant as it requires only standard editor permissions, facilitating privilege escalation via credential access.

## Recommendation

1. Upgrade to a patched version of Pimcore that addresses CVE-2026-55072 immediately.
2. Audit existing `ClassDefinition` entries for UIDs containing non-alphanumeric characters or suspicious SQL keywords.
3. Deploy the Sigma rules below to monitor for suspicious POST requests to the `ClassDefinition` creation and data object retrieval endpoints.
4. Ensure database users operate with the principle of least privilege, specifically restricting access to sensitive tables like `users` from the web application user.
