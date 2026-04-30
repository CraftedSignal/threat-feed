---
title: ArthurFiorette steam-trader 2.1.1 Sensitive Information Exposure
slug: 2024-01-steam-trader-cve
description: CVE-2026-5128 exposes sensitive Steam account data via the /users API endpoint and logs in ArthurFiorette steam-trader 2.1.1, allowing account takeover.
date: "2026-03-30T10:16:02Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-5128
  - steam-trader
  - information-disclosure
  - credential-access
  - account-takeover
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1110
    technique_name: Brute Force
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5128
rules:
  - title: Detect Unauthenticated Steam-Trader Users API Access
    description: Detects unauthenticated access to the /users API endpoint in ArthurFiorette steam-trader, indicating potential CVE-2026-5128 exploitation.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
  - title: Detect Sensitive Data in Steam-Trader Logs
    description: Detects the presence of sensitive Steam account data (username, password, identity_secret, shared_secret) within application logs.
    platform: sigma
    severity: critical
    tactics:
      - collection
      - credential_access
    techniques:
      - T1110
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-5128 identifies a critical vulnerability in version 2.1.1 of the ArthurFiorette steam-trader application. This is a sensitive information exposure issue stemming from two main sources: direct access to the /users API endpoint and insecure logging practices. The vulnerable application, designed for managing Steam trading activities, inadvertently leaks highly sensitive user credentials. As the steam-trader repository is archived and no longer maintained, no patch is available, leaving…
