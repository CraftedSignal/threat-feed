---
title: 9routers Database Exposure and Takeover via Insecure API
slug: 2026-07-9routers-db-exposure
description: A critical vulnerability (CVE-2026-55500) in 9routers versions <= 0.4.71 allows authenticated attackers with a valid JWT token to export the complete database containing plaintext credentials and secrets, and to import a modified database, leading to full system takeover and credential theft.
date: "2026-07-06T21:43:46Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-exploitation
  - data-exfiltration
  - credential-access
  - persistence
  - impact
vendors:
  - 9routers
products:
  - 9router <= 0.4.71
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The `/api/settings/database` endpoint allows full database export... without any authentication requirement beyond the `ALWAYS_PROTECTED` middleware check, which only validates JWT or CLI token.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1530
    technique_name: Credential Dumping
    evidence: 'GET (Export): Returns the complete database including API keys (`key` field in `apiKeys` table), OAuth tokens, and all provider credentials.'
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The exported data includes `apiKeys` with their plaintext `key` values, `providerConnections` with all OAuth tokens, and `settings` with OIDC client secrets.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: 'POST (Import): ...replaces all settings including the password hash, effectively allowing an attacker to set their own password.'
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: 'POST (Import): Accepts arbitrary JSON and performs a complete database wipe-and-replace in a transaction.'
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: 'Availability: Database wipe is possible by importing an empty database'
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-qvfm-67h2-2qfx
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55500
iocs:
  - type: url
    value: http://localhost:20128/api/settings/database
ioc_counts:
  url: 1
rules:
  - title: Detects CVE-2026-55500 Exploitation — 9routers Database Export/Import
    description: Detects exploitation attempts against CVE-2026-55500 in 9routers, where an authenticated attacker accesses the sensitive /api/settings/database endpoint to export or import database content.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - impact
      - initial_access
      - persistence
    techniques:
      - T1078
      - T1190
      - T1485
      - T1530
    data_sources:
      - webserver
rules_count: 1
---

A critical vulnerability, tracked as CVE-2026-55500, has been identified in 9routers versions 0.4.71 and earlier. This flaw resides in the `/api/settings/database` API endpoint, which is intended for database export and import functionalities. Despite being protected by an `ALWAYS_PROTECTED` middleware requiring a valid JWT or CLI token, this protection is deemed insufficient. An attacker, having obtained a valid token (potentially through default credentials like "123456" or other means), can exploit this endpoint to perform a full export of the application's database. This export includes highly sensitive information such as plaintext API keys, OAuth tokens, OIDC client secrets, and hashed user credentials. Furthermore, the attacker can import a modified database, enabling a complete wipe and overwrite of the existing database, which can be leveraged to replace administrator password hashes, gain persistent access, and achieve full system takeover. This vulnerability poses a severe risk to the confidentiality, integrity, and availability of affected 9router instances.

## Attack Chain

1.  **Initial Access / Credential Acquisition**: An attacker identifies an accessible 9router instance and obtains an initial valid JWT or CLI token, potentially leveraging default credentials (e.g., '123456') or other initial access methods.
2.  **Reconnaissance / Sensitive Endpoint Access**: Using the acquired token, the attacker sends an HTTP GET request to the `/api/settings/database` endpoint to understand its functionality and extract current configuration.
3.  **Data Exfiltration / Credential Dumping**: The vulnerable endpoint responds with a full database export, providing the attacker with highly sensitive information, including plaintext API keys, OAuth tokens, OIDC client secrets, and hashed user credentials.
4.  **Data Manipulation**: The attacker analyzes the exfiltrated database content, identifies critical entries (such as administrator password hashes), and modifies them to establish their own privileged access.
5.  **Privilege Escalation / Persistence (Database Import)**: The attacker crafts an HTTP POST request containing the manipulated database payload and sends it to the `/api/settings/database` endpoint, authenticating with their valid token.
6.  **System Control / Database Overwrite**: The 9router application processes this malicious import request, completely overwriting its operational database with the attacker's controlled data, including new administrator credentials.
7.  **Impact / Full Takeover**: The attacker can now log in to the 9router instance using their newly set credentials, gaining full administrative control and potentially leveraging the previously stolen API keys for further malicious activities.

## Impact

The successful exploitation of CVE-2026-55500 leads to severe consequences across multiple domains. Confidentiality is completely breached through the exposure of all stored secrets, including plaintext API keys, OAuth tokens, and OIDC client secrets, which could facilitate lateral movement or access to connected services. Integrity is compromised as attackers can perform a full database replacement with their own controlled data, effectively rewriting all application settings and user credentials. This allows for persistent control and unauthorized modifications. Furthermore, availability can be impacted if an attacker chooses to import an empty or malformed database, leading to a denial of service for the 9router application. This vulnerability enables a complete system takeover.

## Recommendation

*   **Patch Immediately**: Upgrade 9router to a version greater than 0.4.71 to address CVE-2026-55500.
*   **Implement Strong Authentication**: Ensure that highly sensitive endpoints like `/api/settings/database` require multi-factor authentication or re-authentication with current credentials, not just an existing session.
*   **Deploy Sigma Rules**: Deploy the provided Sigma rule to your SIEM to detect attempts to access the `/api/settings/database` endpoint and investigate any alerts.
*   **Review Logs**: Audit webserver access logs for `http://localhost:20128/api/settings/database` (or your production URL) for any suspicious GET or POST requests.
*   **Rotate Credentials**: Immediately rotate all API keys, OAuth tokens, and other secrets if an instance of 9router was running a vulnerable version.
