---
title: Citrix Systems NetScaler Vulnerabilities Allow Information Disclosure and Session Hijacking
slug: 2026-03-netscaler-vulns
description: An anonymous or authenticated remote attacker can exploit multiple vulnerabilities in Citrix Systems NetScaler to disclose information and take over a user session.
date: "2026-03-24T12:36:02Z"
severities:
  - critical
tags:
  - citrix
  - netscaler
  - vulnerability
  - session-hijacking
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0836
rules:
  - title: Detect Suspicious NetScaler Session Hijacking
    description: Detects potential session hijacking attempts on NetScaler based on User-Agent anomalies.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect NetScaler Information Disclosure Attempts
    description: Detects attempts to exploit information disclosure vulnerabilities on NetScaler by looking for specific URI patterns.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1592.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Citrix Systems NetScaler is vulnerable to multiple security flaws that could be exploited by remote attackers. These vulnerabilities, which can be leveraged by both anonymous and authenticated users, can lead to sensitive information disclosure and complete user session hijacking. The specific versions affected are not detailed in this advisory, but the broad scope suggests that numerous deployments are potentially at risk. Successful exploitation could grant unauthorized access to critical…
