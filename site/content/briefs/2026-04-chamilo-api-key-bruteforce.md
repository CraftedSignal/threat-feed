---
title: Chamilo LMS REST API Key Brute-Force Vulnerability (CVE-2026-33710)
slug: 2026-04-chamilo-api-key-bruteforce
description: Chamilo LMS versions prior to 1.11.38 and 2.0.0-RC.3 generate predictable REST API keys, allowing attackers with knowledge of a username and approximate key creation time to brute-force access.
date: "2026-04-11T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve-2026-33710
  - chamilo
  - api-key
  - brute-force
  - webserver
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
cves:
  - id: CVE-2026-33710
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33710
  - https://github.com/chamilo/chamilo-lms/security/advisories/GHSA-rpmg-j327-mr39
  - https://github.com/chamilo/chamilo-lms/commit/4448701bb8ec557e94ef02d19c72cbe9c49c2d09
  - https://github.com/chamilo/chamilo-lms/commit/e7400dd840586ae134b286d0a2374f3d269a9a9d
rules:
  - title: Detect Chamilo LMS API Brute-Force Attempts via Multiple Failed Authentication Responses
    description: Detects potential brute-force attacks against the Chamilo LMS API by monitoring for multiple failed authentication responses from the web server.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
      - linux
  - title: Detect Chamilo LMS API Access from Uncommon User Agent
    description: Detects potential API access from unusual user agents, potentially indicating automated or malicious activity against Chamilo LMS.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chamilo LMS, a popular learning management system, contains a vulnerability in versions prior to 1.11.38 and 2.0.0-RC.3 related to the generation of REST API keys (CVE-2026-33710). The API keys are generated using a flawed algorithm: `md5(time() + (user_id * 5) - rand(10000, 10000))`. Due to `rand(10000, 10000)` always returning 10000, the formula simplifies to `md5(timestamp + user_id*5 - 10000)`. An attacker knowing a valid username and a rough estimate of when the API key was generated can brute-force the key due to the limited entropy. This vulnerability allows unauthorized access to the Chamilo LMS REST API. The vulnerability was reported and patched in versions 1.11.38 and 2.0.0-RC.3. This poses a significant threat to educational institutions and organizations using vulnerable versions of Chamilo LMS.

## Attack Chain

1.  Attacker identifies a target Chamilo LMS instance running a vulnerable version (prior to 1.11.38 or 2.0.0-RC.3).
2.  Attacker obtains a valid username on the target Chamilo LMS instance through OSINT or credential stuffing.
3.  Attacker estimates the API key creation time. This might be inferred from user activity or system logs.
4.  Attacker crafts a script to generate potential API keys based on the predictable formula `md5(timestamp + user_id*5 - 10000)` using the known username and estimated timestamp.
5.  The script iterates through a range of timestamps around the estimated creation time, generating corresponding MD5 hashes.
6.  Attacker sends API requests with the generated API keys to the Chamilo LMS server.
7.  The server validates the API key against the user.
8.  Upon successful validation, the attacker gains unauthorized access to the Chamilo LMS REST API, potentially allowing them to modify course content, access user data, or perform other malicious actions.

## Impact

Successful exploitation of CVE-2026-33710 can lead to unauthorized access to sensitive data within the Chamilo LMS, including user information, course materials, and grades. This could result in data breaches, academic fraud, and reputational damage for affected organizations. The vulnerability affects all organizations running vulnerable versions of Chamilo LMS; the number of victims is correlated to the number of vulnerable deployments.

## Recommendation

*   Upgrade Chamilo LMS installations to version 1.11.38 or 2.0.0-RC.3 or later to patch CVE-2026-33710.
*   Monitor web server logs for unusual API requests originating from unexpected IP addresses, especially those containing potentially valid API keys by deploying the provided Sigma rule.
*   Implement rate limiting on API endpoints to mitigate brute-force attempts.
*   If upgrading is not immediately feasible, consider temporarily disabling the REST API.
*   Review and audit user permissions within Chamilo LMS to minimize the impact of potential unauthorized access.
