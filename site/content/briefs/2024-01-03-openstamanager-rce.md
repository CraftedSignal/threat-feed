---
brief_id: brief-2024-01-03-openstamanager-rce
event_id: brief-2024-01-03-openstamanager-rce
revision: 1
activity_at: "2024-01-03T12:00:00Z"
title: OpenSTAManager Unauthenticated Remote Code Execution via Insecure Deserialization
slug: 2024-01-03-openstamanager-rce
description: OpenSTAManager is vulnerable to remote code execution due to insecure deserialization in the OAuth2 component, allowing unauthenticated attackers to execute arbitrary commands by injecting a malicious serialized object into the `zz_oauth2` table.
date: "2024-01-03T12:00:00Z"
lastmod: "2026-11-01T08:57:41Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
cpes:
  - cpe:2.3:a:devcode:openstamanager:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HACKERKING24-CVE-2026-29782-OPENSTAMANAGER-RCE&utm_source=rss&utm_medium=rss
tags:
  - openstamanager
  - rce
  - deserialization
  - sqli
  - webserver
vendors:
  - Devcode
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    subtechnique_id: T1505.003
    subtechnique_name: Web Shell
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    subtechnique_id: T1204.002
    subtechnique_name: Malicious File
cves:
  - id: CVE-2026-29782
    cvss: 7.2
    epss: 0.00591
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-whv5-4q2f-q68g
  - https://github.com/devcode-it/openstamanager/security/advisories/GHSA-2fr7-cc4f-wh98
  - https://github.com/ambionics/phpggc
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HACKERKING24-CVE-2026-29782-OPENSTAMANAGER-RCE&utm_source=rss&utm_medium=rss
rules:
  - title: Detect OpenSTAManager OAuth2 Deserialization Trigger
    description: Detects attempts to trigger the insecure deserialization vulnerability in OpenSTAManager's oauth2.php endpoint by monitoring GET requests with a known 'state' parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - webserver
      - linux
  - title: Detect OpenSTAManager Aggiornamenti SQL Injection Attempt
    description: Detects POST requests to actions.php with the op=risolvi-conflitti-database parameter, indicative of potential SQL injection attempts in the Aggiornamenti module.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
updates:
  - at: "2026-11-01T08:57:41Z"
    level: L2
    summary: poc_available; added CVE-2026-29782
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-HACKERKING24-CVE-2026-29782-OPENSTAMANAGER-RCE&utm_source=rss&utm_medium=rss
---

OpenSTAManager is vulnerable to an unauthenticated remote code execution (RCE) vulnerability due to insecure deserialization in the `oauth2.php` endpoint. This endpoint lacks authentication and deserializes data from the `access_token` field in the `zz_oauth2` table without any class restrictions. An attacker who can write to the `zz_oauth2` table can inject a malicious serialized PHP object, which, upon deserialization, allows arbitrary command execution on the server as the `www-data` user. This vulnerability can be exploited in conjunction with an arbitrary SQL injection vulnerability in the Aggiornamenti module ([GHSA-2fr7-cc4f-wh98](https://github.com/devcode-it/openstamanager/security/advisories/GHSA-2fr7-cc4f-wh98)) to achieve unauthenticated RCE. The reported vulnerability affects OpenSTAManager version 2.10.1.

## Attack Chain

1. **SQL Injection:** An authenticated attacker with administrative privileges exploits an arbitrary SQL injection vulnerability in the Aggiornamenti module (`op=risolvi-conflitti-database`).
2. **Malicious Payload Insertion:** The attacker crafts a SQL query to insert a malicious serialized PHP object into the `access_token` field of the `zz_oauth2` table, using a known `state` value (e.g., `poc-xxx`).
3. **DDL Statement for Persistence:** The SQL query includes DDL statements (`CREATE TABLE`, `DROP TABLE`) to force a MySQL commit and persist the injected payload, bypassing transaction rollback.
4. **Unauthenticated Request:** The attacker sends an unauthenticated GET request to `/oauth2.php` with the `state` parameter set to the known value used during payload injection (e.g., `oauth2.php?state=poc-xxx&code=x`).
5. **Data Retrieval:** The `oauth2.php` script retrieves the record from the `zz_oauth2` table based on the provided `state` parameter.
6. **Deserialization:** The script calls `unserialize()` on the `access_token` field of the retrieved record, triggering the deserialization of the injected malicious PHP object.
7. **Gadget Chain Execution:** The deserialization triggers a gadget chain (e.g., Laravel/RCE22) that leads to the execution of arbitrary commands.  Specifically, the `PendingBroadcast.__destruct()` method is called, triggering the `system()` function with an attacker-controlled command.
8. **Remote Code Execution:** The attacker-specified command is executed on the server as the `www-data` user.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary commands on the affected OpenSTAManager server. The attacker gains the privileges of the `www-data` user, potentially leading to complete system compromise, data theft, or denial of service. Due to the combination of SQL injection and insecure deserialization, the impact is rated as critical. The number of potential victims is equal to the number of OpenSTAManager instances exposed to the internet or accessible from untrusted networks.

## Recommendation

*   Apply the patch or upgrade to a non-vulnerable version of OpenSTAManager as soon as it becomes available.
*   Deploy the Sigma rule `Detect-OpenSTAManager-OAuth2-Deserialization-Trigger` to detect attempts to trigger the insecure deserialization vulnerability via crafted HTTP requests to the `oauth2.php` endpoint.
*   Review and harden database access controls to prevent unauthorized modifications to the `zz_oauth2` table, mitigating the SQL injection attack vector.
*   Monitor web server logs for suspicious POST requests to `actions.php` with the `op=risolvi-conflitti-database` parameter, indicative of potential SQL injection attempts (GHSA-2fr7-cc4f-wh98).
*   Implement strict input validation and sanitization to prevent SQL injection vulnerabilities in OpenSTAManager modules.
