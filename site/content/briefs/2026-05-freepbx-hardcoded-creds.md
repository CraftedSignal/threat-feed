---
title: FreePBX Security-Reporting userman Unauthenticated Hard-Coded Credentials Vulnerability
slug: 2026-05-freepbx-hardcoded-creds
description: FreePBX Security-Reporting userman versions 16.0.45 and prior (FreePBX 16) and 17.0.7 and prior (FreePBX 17) contain a critical vulnerability due to unauthenticated use of hard-coded credentials in the UCP interface, potentially allowing unauthorized access.
date: "2026-05-15T19:27:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - freepbx
  - hardcoded-credentials
  - voip
vendors:
  - FreePBX
products:
  - FreePBX Security-Reporting userman (FreePBX 16)
  - FreePBX Security-Reporting userman (FreePBX 17)
references:
  - https://cyber.gc.ca/en/alerts-advisories/freepbx-security-advisory-av26-474
  - https://github.com/FreePBX/security-reporting/security/advisories/GHSA-m55x-h47x-v3gx
  - https://github.com/FreePBX/security-reporting/security/advisories?state=published
rules:
  - title: Detect Unauthenticated Access to FreePBX UCP Interface
    description: Detects unauthenticated requests to the FreePBX UCP interface, which could indicate exploitation of hardcoded credential vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious POST Requests to FreePBX UCP Login
    description: Detects suspicious POST requests to the FreePBX UCP login page, which could be indicative of brute-force attacks or credential stuffing.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1110
    data_sources:
      - webserver
rules_count: 2
---

On May 15, 2026, FreePBX published a security advisory addressing a critical vulnerability affecting the Security-Reporting userman module. This vulnerability impacts FreePBX 16 versions 16.0.45 and prior, and FreePBX 17 versions 17.0.7 and prior. The vulnerability stems from the use of hard-coded credentials within the User Control Panel (UCP) interface, allowing unauthenticated attackers to potentially gain unauthorized access to the system. Successful exploitation could lead to sensitive data exposure, configuration modification, or complete system compromise. This is a critical issue due to the widespread use of FreePBX in telecommunications infrastructure.

## Attack Chain

1.  Attacker identifies a vulnerable FreePBX instance with an exposed UCP interface.
2.  Attacker accesses the UCP interface without authentication.
3.  Attacker leverages the hard-coded credentials present in the vulnerable Security-Reporting userman module.
4.  Attacker gains unauthorized access to user accounts and system settings.
5.  Attacker modifies user permissions or creates new administrative accounts.
6.  Attacker uses the elevated privileges to access sensitive call records and configuration files.
7.  Attacker may install malicious modules to further compromise the system.
8.  Attacker achieves full system compromise, potentially leading to eavesdropping on calls, denial-of-service, or further lateral movement within the network.

## Impact

Successful exploitation of this vulnerability could lead to complete compromise of the FreePBX system. This includes unauthorized access to call records, modification of system configuration, and the potential for eavesdropping on phone calls. Organizations relying on FreePBX for their telecommunications infrastructure are at risk of data breaches, service disruptions, and financial losses. Given the widespread use of FreePBX, a large number of organizations could be affected by this vulnerability.

## Recommendation

*   Immediately upgrade FreePBX Security-Reporting userman module to versions later than 16.0.45 (FreePBX 16) and 17.0.7 (FreePBX 17) to remediate the hard-coded credentials vulnerability.
*   Monitor access logs for suspicious activity related to the UCP interface, looking for unauthenticated access attempts (reference: overview).
*   Implement network segmentation to limit the exposure of the FreePBX system and UCP interface to internal networks only.
