---
title: Unauthenticated SQL Injection in IBM API Connect (CVE-2026-9074)
slug: 2026-07-ibm-api-connect-sqli
description: IBM API Connect versions 10.0.8.0 through 10.0.8.9 and 12.1.0.0 through 12.1.0.3 are vulnerable to an unauthenticated SQL injection (CVE-2026-9074) in the password reset functionality, potentially leading to unauthorized data access or authentication bypass.
date: "2026-07-08T16:24:32Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - sql-injection
  - web-vulnerability
  - critical-vulnerability
  - api-management
vendors:
  - IBM
products:
  - API Connect (10.0.8.0)
  - API Connect (10.0.8.1)
  - API Connect (10.0.8.2)
  - API Connect (10.0.8.3)
  - API Connect (10.0.8.4)
  - API Connect (10.0.8.5)
  - API Connect (10.0.8.6)
  - API Connect (10.0.8.7)
  - API Connect (10.0.8.8)
  - API Connect (10.0.8.9)
  - API Connect (12.1.0.0)
  - API Connect (12.1.0.1)
  - API Connect (12.1.0.2)
  - API Connect (12.1.0.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: IBM API Connect ... contains an unauthenticated SQL injection vulnerability in the password reset functionality.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: potentially leading to unauthorized data access or authentication bypass.
    confidence_band: med
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: potentially allowing an attacker to inject malicious SQL queries ... without prior authentication.
    confidence_band: med
cves:
  - id: CVE-2026-9074
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9074
  - https://www.ibm.com/support/pages/node/7278218
  - https://www.ibm.com/support/pages/node/7278909
rules:
  - title: Detect CVE-2026-9074 Exploitation Attempt - IBM API Connect SQL Injection
    description: Detects CVE-2026-9074 exploitation attempts against IBM API Connect password reset functionality by looking for common SQL injection patterns in web server logs. This may indicate an unauthenticated attacker attempting to compromise the system.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1587
    data_sources:
      - webserver
rules_count: 1
---

A critical unauthenticated SQL injection vulnerability, tracked as CVE-2026-9074 (CVSS v3.1 Base Score: 9.1), affects IBM API Connect versions 10.0.8.0 through 10.0.8.9 and 12.1.0.0 through 12.1.0.3. This flaw resides within the password reset functionality of the API management platform, allowing a remote attacker to inject malicious SQL queries without requiring any prior authentication. Successful exploitation of this vulnerability could enable an attacker to bypass authentication mechanisms, gain unauthorized access to sensitive database information, or potentially manipulate data, posing a significant risk to the integrity and confidentiality of the affected systems and user accounts. Organizations utilizing the specified vulnerable versions of IBM API Connect are strongly urged to apply the available patches immediately to mitigate this severe risk.

## Attack Chain

1. An unauthenticated attacker identifies an exposed IBM API Connect instance running a vulnerable version (10.0.8.0-10.0.8.9 or 12.1.0.0-12.1.0.3).
2. The attacker accesses the publicly available password reset functionality of the IBM API Connect web interface.
3. The attacker crafts and submits a specially malformed request to the password reset endpoint, embedding SQL injection payloads within input fields or parameters that are processed by the application's backend database.
4. The vulnerable application processes the malicious input without proper sanitization, leading to the execution of the attacker's arbitrary SQL commands within the database.
5. Depending on the crafted payload, the attacker might retrieve sensitive information from the database (e.g., user credentials, API keys) or bypass authentication to gain unauthorized access to user accounts.
6. Upon successful data exfiltration or authentication bypass, the attacker can leverage the compromised credentials or access tokens for further malicious activities within the API Connect environment.

## Impact

Successful exploitation of CVE-2026-9074 can lead to severe consequences for organizations. Due to the unauthenticated nature of the vulnerability, any attacker can initiate the exploitation. The primary impacts include unauthorized access to sensitive data stored in the backend database, such as user account details, API configurations, or other critical system information. Attackers could also achieve authentication bypass, gaining full control over administrative or user accounts within the IBM API Connect instance. This could lead to further compromise of managed APIs, data exfiltration, service disruption, or unauthorized modification of system settings, severely compromising the confidentiality and integrity of the API management platform and the services it exposes.

## Recommendation

* Patch CVE-2026-9074 immediately by updating IBM API Connect to a fixed version beyond 10.0.8.9 or 12.1.0.3, as described in the IBM support advisories referenced.
* Deploy the Sigma rule "Detect CVE-2026-9074 Exploitation Attempt - IBM API Connect SQL Injection" to your SIEM and tune for your environment to detect attempts against the password reset functionality.
* Monitor web server logs for suspicious requests to password reset endpoints containing common SQL injection patterns.
