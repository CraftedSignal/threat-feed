---
title: Authentication Bypass and Privilege Escalation in ArcadeDB
slug: 2026-08-arcadedb-privesc
description: ArcadeDB versions before 26.8.1 contain a vulnerability in the gRPC transaction executor that allows authenticated readers to execute arbitrary JavaScript, leading to server-wide privilege escalation.
date: "2026-08-18T12:51:42Z"
lastmod: "2026-08-18T12:52:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - privilege-escalation
  - database-security
  - cve-2026-75843
  - vulnerability
  - authentication-bypass
vendors:
  - ArcadeData
products:
  - ArcadeDB
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can execute executeCommand with a transaction ID to run unrestricted JavaScript that creates server-wide administrator accounts.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can issue insert, find, update, delete, and create commands against any database by connecting to port 27017 without credentials.
    confidence_band: high
cves:
  - id: CVE-2026-75843
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75843
  - https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-p29f-345w-4qwf
  - https://www.vulncheck.com/advisories/arcadedb-before-privilege-escalation-via-grpc-transaction
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75852
  - https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-fq9c-x968-g278
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75854
  - https://github.com/ArcadeData/arcadedb/security/advisories/GHSA-m46c-jh3x-xwrp
  - https://www.vulncheck.com/advisories/arcadedb-redis-wire-protocol-plugin-missing-authentication
rules:
  - title: Detect ArcadeDB Unauthorized MongoDB Protocol Access Attempt
    description: Detects potential exploitation of CVE-2026-75852 by monitoring for unauthenticated MongoDB wire-protocol traffic targeted at ArcadeDB instances
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
rules_count: 1
updates:
  - at: "2026-08-18T12:52:06Z"
    level: L2
    summary: 'added detection rule: Detect ArcadeDB Unauthorized MongoDB Protocol Access Attempt'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75852
  - at: "2026-08-18T12:52:14Z"
    level: L2
    summary: added coverage for ArcadeDB
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-75854
---

ArcadeDB versions prior to 26.8.1 contain a critical security vulnerability (CVE-2026-75843) stemming from improper privilege management within the gRPC transaction executor thread. The issue occurs specifically during the 'beginTransaction' method, where the application fails to bind the authenticated principal to the executor thread. 

This failure allows an attacker possessing only read-level authentication to bypass security checks intended to restrict scripting actions. By invoking the 'executeCommand' method and supplying a valid transaction ID, an attacker can execute unrestricted JavaScript on the server. This primitive can be leveraged to manipulate the database configuration, modify security settings, or programmatically create new administrative accounts, resulting in full server compromise. The vulnerability is considered highly critical due to the ease of exploitation by existing users to achieve total administrative control.

## Attack Chain

1. Attacker establishes a connection to the target ArcadeDB instance using valid low-privileged reader credentials.
2. Attacker initiates a gRPC session targeting the transaction executor service.
3. Attacker triggers the vulnerable 'beginTransaction' call to establish a transaction context.
4. Attacker crafts a malicious JavaScript payload designed to create a new administrative user.
5. Attacker calls the 'executeCommand' function within the established transaction, passing the malicious JavaScript as an argument.
6. The server-side thread, having failed to bind the security principal, processes the 'executeCommand' request without authorization checks.
7. The arbitrary JavaScript executes with elevated privileges on the database server.
8. A new administrative account is created, providing the attacker with persistent, full-access administrative control.

## Impact

Successful exploitation of CVE-2026-75843 grants an authenticated attacker complete administrative access to the ArcadeDB instance. This can lead to the total loss of data confidentiality, integrity, and availability. Attackers can exfiltrate sensitive database contents, modify records, or deploy persistent backdoors within the database environment. Organizations running versions of ArcadeDB earlier than 26.8.1 are at significant risk of total server takeover by any compromised user account.

## Recommendation

* Upgrade all instances of ArcadeDB to version 26.8.1 or later immediately to patch CVE-2026-75843.
* Audit logs for unauthorized account creation activity or suspicious JavaScript execution patterns, particularly those originating from existing low-privileged accounts.
* Restrict network access to the gRPC interface of the database to trusted internal segments to prevent unauthorized connection attempts.
* Rotate credentials for all existing accounts, as attackers may have already leveraged this vulnerability to create hidden administrative backdoors.
