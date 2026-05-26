---
title: NordVPN Denial-of-Service Vulnerability (CVE-2018-25368)
slug: 2026-05-nordvpn-dos
description: NordVPN version 6.14.31 is vulnerable to a denial-of-service attack (CVE-2018-25368) where an unauthenticated attacker can crash the application by submitting an excessively long string in the password field.
date: "2026-05-26T14:14:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - dos
  - denial-of-service
  - cve-2018-25368
vendors:
  - NordVPN
products:
  - Nord VPN 6.14.31
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2018-25368
    cvss: 7.5
    epss: 0.00048
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25368
  - https://nordvpn.com/download/
  - https://www.exploit-db.com/exploits/45304
  - https://www.vulncheck.com/advisories/nord-vpn-denial-of-service-via-password-field
rules:
  - title: Detect NordVPN Long Password DoS Attempt
    description: Detects CVE-2018-25368 exploitation attempt by monitoring process creation events related to the NordVPN client with unusually long command-line arguments.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
  - title: Detect NordVPN Crash Events
    description: Detects NordVPN process termination events that may indicate a crash due to CVE-2018-25368 exploitation.
    platform: sigma
    severity: low
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

NordVPN version 6.14.31 is susceptible to a denial-of-service (DoS) vulnerability, identified as CVE-2018-25368. This flaw allows an unauthenticated attacker to crash the NordVPN application by providing an excessively long string in the password input field during the authentication process. Specifically, an attacker can paste a large buffer of repeated characters into the password field, leading to a crash upon attempting to authenticate. This vulnerability was reported and assigned CVE-2018-25368.

## Attack Chain

1. The attacker identifies a vulnerable NordVPN client version (6.14.31).
2. The attacker opens the NordVPN application login screen.
3. The attacker inputs a valid or arbitrary username.
4. The attacker pastes an excessively long string (buffer of repeated characters) into the password field.
5. The attacker attempts to authenticate with the long password.
6. The NordVPN application attempts to allocate memory for the excessively long string.
7. Due to insufficient input validation, the application attempts to allocate an excessive amount of memory.
8. The application crashes due to a memory allocation error, resulting in a denial of service.

## Impact

Successful exploitation of CVE-2018-25368 results in a denial-of-service condition, causing the NordVPN application to crash. This can disrupt VPN service for individual users and potentially impact organizations relying on NordVPN for secure communication. The vulnerability allows unauthenticated attackers to repeatedly crash the application, preventing legitimate users from establishing a VPN connection. The CVSS v3.1 base score is 7.5, indicating a high impact on availability.

## Recommendation

*   Upgrade NordVPN to a version beyond 6.14.31 to patch CVE-2018-25368, as recommended by NordVPN.
*   Deploy the Sigma rule `Detect NordVPN Long Password DoS Attempt` to identify potential exploitation attempts based on process creation events related to the NordVPN client.
*   Monitor application logs for abnormal memory allocation errors that may indicate exploitation of CVE-2018-25368.
