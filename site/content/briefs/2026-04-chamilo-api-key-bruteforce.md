---
title: Chamilo LMS REST API Key Brute-Force Vulnerability (CVE-2026-33710)
slug: 2026-04-chamilo-api-key-bruteforce
description: Chamilo LMS versions prior to 1.11.38 and 2.0.0-RC.3 generate predictable REST API keys, allowing attackers with knowledge of a username and approximate key creation time to brute-force access.
date: "2026-04-11T12:00:00Z"
severities:
  - high
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

Chamilo LMS, a popular learning management system, contains a vulnerability in versions prior to 1.11.38 and 2.0.0-RC.3 related to the generation of REST API keys (CVE-2026-33710). The API keys are generated using a flawed algorithm: `md5(time() + (user_id * 5) - rand(10000, 10000))`. Due to `rand(10000, 10000)` always returning 10000, the formula simplifies to `md5(timestamp + user_id*5 - 10000)`. An attacker knowing a valid username and a rough estimate of when the API key was generated can…
