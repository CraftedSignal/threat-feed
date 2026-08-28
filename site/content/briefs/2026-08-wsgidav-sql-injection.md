---
title: Blind SQL Injection in WsgiDAV MySQLBrowserProvider
slug: 2026-08-wsgidav-sql-injection
description: The WsgiDAV MySQLBrowserProvider sample module is vulnerable to blind SQL injection via unsanitized URL input, allowing unauthenticated attackers to extract database content.
date: "2026-08-28T21:17:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wsgidav:wsgidav:*:*:*:*:*:*:*:*
vendors:
  - WsgiDAV
products:
  - WsgiDAV (<= 4.3.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any user who can reach a share backed by this provider can inject SQL through the URL.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: An anonymous attacker can read arbitrary data from the backing database.
    confidence_band: high
cves:
  - id: CVE-2026-55509
references:
  - https://github.com/advisories/GHSA-p6gw-4frg-j7jw
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55509
rules:
  - title: Detect CVE-2026-55509 Exploitation - SQL Injection in WsgiDAV URL Path
    description: Detects potential blind SQL injection attempts against WsgiDAV by monitoring for SQL metacharacters within URI requests to paths associated with the MySQLBrowserProvider.
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
    - action: Inventory all WsgiDAV instances to identify if MySQLBrowserProvider is enabled
      owner: IT Operations
      due: 24h
      evidence: The provider's vulnerability is only active if explicitly enabled.
  mitigation_plan:
    - priority: immediate
      action: Upgrade WsgiDAV to 4.3.5 or later
      owner: IT Operations
      addresses: CVE-2026-55509
      evidence: GHSA-p6gw-4frg-j7jw
---

The WsgiDAV project contains a sample module named `MySQLBrowserProvider` that is vulnerable to blind SQL injection (CVE-2026-55509). The vulnerability stems from improper input sanitization where the record key provided in a URL request is directly concatenated into a SQL `WHERE` clause. While the provider is not enabled by default, deployments that explicitly configure it to back a share are exposed.

Because the provider performs an existence check during standard `GET` requests, an attacker does not require authentication or write access to exploit the flaw. By injecting SQL conditions into the URL path, an attacker can use a boolean status-code oracle - where a successful query result or error returns a 500 status and a non-existent record returns a 404 - to perform bit-by-bit data extraction from the backing database. This allows for the exfiltration of sensitive table data reachable by the database user account configured in the provider.

## Attack Chain

1. Attacker identifies a WsgiDAV instance exposing a share backed by `MySQLBrowserProvider`.
2. Attacker crafts a malicious URL path formatted as `/db/<table_name>/<injected_sql_key>`.
3. Attacker uses a boolean SQL injection payload, such as `0' OR (SELECT ASCII(MID((QUERY),1,1))>100) OR '1'='2` in the key parameter.
4. The `MySQLBrowserProvider` receives the request and concatenates the injected string directly into the `SELECT id FROM table WHERE id = '<injected_key>'` query.
5. The backend database executes the injected SQL.
6. The application returns an HTTP 500 if the injected condition is true (due to internal state handling) or an HTTP 404 if false.
7. Attacker iteratively automates these requests to exfiltrate arbitrary data from the database.

## Impact

Successful exploitation leads to unauthorized access and exfiltration of sensitive information contained within the MySQL database linked to the WsgiDAV share. The scope of impact is limited to the privileges of the database user configured in the provider. As this is an unauthenticated vector on any share using the provider, it represents a high risk for data confidentiality in affected deployments.

## Recommendation

Prioritize the remediation of any WsgiDAV instance utilizing the `MySQLBrowserProvider`.
- Disable the `MySQLBrowserProvider` module in the WsgiDAV configuration if it is not strictly required.
- Upgrade WsgiDAV to a version where this vulnerability is resolved.
- Implement access control lists (ACLs) or web-level authentication for any share using the `MySQLBrowserProvider` to prevent unauthenticated access.
- Review web access logs for requests to paths matching `/db/*/*` containing SQL syntax characters (e.g., `'`, `--`, `UNION`, `SELECT`).
