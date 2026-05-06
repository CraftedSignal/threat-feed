---
title: Rucio SQL Injection Vulnerability in DID Search API
slug: 2026-05-rucio-sql-injection
description: A SQL injection vulnerability exists in the Oracle path of `FilterEngine.create_sqla_query` in Rucio, allowing any authenticated user to execute arbitrary SQL against the backend database via the DID search endpoint, potentially leading to full database compromise and data exfiltration.
date: "2026-05-07T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - rucio
  - cve-2026-29080
  - web-application
vendors:
  - Oracle
  - pip
products:
  - rucio
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1020
    technique_name: Data Exfiltration
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.005
    technique_name: 'Command and Scripting Interpreter: Visual Basic Script'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-vjr5-c9qv-hgm3
rules:
  - title: Detect Rucio SQL Injection Attempt via DID Search API
    description: Detects potential SQL injection attempts in the Rucio DID search API by looking for suspicious SQL syntax in the cs-uri-query field.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Rucio DID Search API Abuse
    description: Detects excessive calls to the Rucio DID search API which can indicate SQL injection probing.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A SQL injection vulnerability (CVE-2026-29080) has been identified in Rucio's `FilterEngine.create_sqla_query` function, specifically affecting Oracle database backends. The vulnerability resides in the DID search API (`GET /dids/<scope>/dids/search`) and allows any authenticated Rucio user to execute arbitrary SQL commands. This is due to attacker-controlled filter keys and values being directly interpolated into `sqlalchemy.text` via Python's `str.format`, bypassing proper parameterization. The issue affects Rucio versions >= 1.27.0 and < 35.8.5, versions >= 36.0.0 and < 38.5.5, versions >= 39.0.0 and < 39.4.2, and versions >= 40.0.0 and < 40.1.1 when using the default `json_meta` metadata plugin configuration with an Oracle database. Successful exploitation can lead to the extraction of sensitive data, including authentication tokens, password hashes, and managed data identifiers, as well as potential data modification or remote code execution.

## Attack Chain

1. An attacker authenticates to the Rucio system using any supported authentication method (userpass, x509, OIDC, SAML, SSH, GSS).
2. The attacker crafts a malicious HTTP GET request to the `/dids/<scope>/dids/search` endpoint.
3. The crafted request includes SQL injection payloads within the filter keys or values of the request parameters.
4. Rucio's `FilterEngine.create_sqla_query` function processes the request and incorrectly interpolates the attacker-controlled input directly into a SQL query string.
5. The malicious SQL query is executed against the Oracle backend database.
6. The attacker extracts sensitive information from the database, such as user credentials, authentication tokens, and data management policies.
7. The attacker uses stolen authentication tokens to impersonate other users and gain unauthorized access to data.
8. The attacker modifies data management rules or inserts malicious data into the Rucio system.

## Impact

Successful exploitation of this vulnerability allows attackers to gain full read access to the Rucio database, potentially affecting all Oracle-based Rucio deployments using the default `json_meta` configuration. Attackers can extract sensitive information, including password hashes, authentication tokens, and storage endpoint credentials. The extracted password hashes, combined with weak hashing algorithms (single-iteration SHA-256), can be cracked relatively easily. Stolen authentication tokens enable immediate session hijacking. Furthermore, attackers can modify data or potentially achieve remote code execution via Oracle features like `UTL_HTTP` or Java stored procedures. This can lead to data breaches, service disruption, and complete system compromise.

## Recommendation

*   Upgrade Rucio to a patched version >= 35.8.5, >= 38.5.5, >= 39.4.2, or >= 40.1.1 to remediate CVE-2026-29080.
*   For Oracle deployments, review and harden database user privileges to limit the impact of potential SQL injection attacks.
*   Monitor Rucio web server logs for suspicious requests to the `/dids/<scope>/dids/search` endpoint containing potentially malicious SQL syntax. Deploy the Sigma rule `Detect Rucio SQL Injection Attempt via DID Search API` to detect this behavior.
*   Implement enhanced password hashing algorithms (e.g., bcrypt, Argon2) to mitigate the impact of password hash extraction.
