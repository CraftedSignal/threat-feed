---
title: 'CVE-2021-47942: Home Assistant Community Store (HACS) Path Traversal Vulnerability'
slug: 2026-05-hacs-path-traversal
description: Home Assistant Community Store (HACS) 1.10.0 is vulnerable to a path traversal, allowing unauthenticated attackers to read sensitive files by traversing directories via the /hacsfiles/ endpoint, leading to potential account takeover.
date: "2026-05-16T16:19:57Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - path-traversal
  - account-takeover
  - hacs
  - cve-2021-47942
vendors:
  - home-assistant
products:
  - Home Assistant Community Store (HACS) 1.10.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2021-47942
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-47942
  - https://github.com/hacs/integration
  - https://www.exploit-db.com/exploits/49495
  - https://www.home-assistant.io/
  - https://www.vulncheck.com/advisories/home-assistant-community-store-path-traversal-account-takeover
rules:
  - title: Detect HACS Path Traversal Attempt
    description: Detects CVE-2021-47942 exploitation — Path traversal attempts in Home Assistant Community Store (HACS) via the /hacsfiles/ endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Access to Sensitive .storage/auth File via HACS
    description: Detects attempts to access the sensitive .storage/auth file using the path traversal vulnerability in HACS (CVE-2021-47942).
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

Home Assistant Community Store (HACS) version 1.10.0 contains a path traversal vulnerability, identified as CVE-2021-47942, which enables unauthenticated attackers to read arbitrary sensitive files on the system. The vulnerability resides in the `/hacsfiles/` endpoint, which lacks proper input validation, allowing directory traversal. Successful exploitation grants attackers access to sensitive files such as `.storage/auth`, which contains user credentials and refresh tokens. This allows attackers to craft valid JWT tokens and gain administrative access to Home Assistant instances, potentially compromising the entire smart home ecosystem managed by the affected instance. The vulnerability was reported in May 2026.

## Attack Chain

1. An unauthenticated attacker sends a crafted HTTP request to the `/hacsfiles/` endpoint with a path traversal sequence in the URL.
2. The vulnerable application fails to properly sanitize the input, allowing the attacker to traverse the file system.
3. The attacker targets the `.storage/auth` file, which contains sensitive user credentials and refresh tokens.
4. The application reads and returns the contents of the targeted file to the attacker.
5. The attacker extracts user credentials and refresh tokens from the obtained `.storage/auth` file.
6. The attacker uses the extracted information to craft valid JWT tokens.
7. The attacker authenticates to the Home Assistant instance using the crafted JWT tokens.
8. The attacker gains administrative access to the Home Assistant instance, allowing full control over connected devices and configurations.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to gain administrative control over Home Assistant instances. This can lead to unauthorized access to and manipulation of connected smart home devices, exposure of sensitive user data, and potential disruption of home automation systems. The impact ranges from privacy violations and service disruption to complete compromise of the affected smart home environment. Given the widespread use of Home Assistant, a successful attack could affect a significant number of users.

## Recommendation

*   Deploy the Sigma rule `Detect HACS Path Traversal Attempt` to detect requests with path traversal sequences targeting the `/hacsfiles/` endpoint.
*   Apply input validation and sanitization to the `/hacsfiles/` endpoint to prevent directory traversal attacks, addressing CVE-2021-47942.
*   Monitor web server logs for suspicious activity related to the `/hacsfiles/` endpoint, as logged by the "webserver" category.
*   Upgrade to a patched version of Home Assistant Community Store (HACS) that addresses the path traversal vulnerability.
