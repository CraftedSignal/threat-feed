---
title: Hirschmann HiEOS HTTP(S) Management Module Authentication Bypass (CVE-2024-14034)
slug: 2026-04-hieos-auth-bypass
description: Hirschmann HiEOS devices contain an authentication bypass vulnerability (CVE-2024-14034) in the HTTP(S) management module, allowing unauthenticated remote attackers to gain administrative access by sending specially crafted HTTP(S) requests.
date: "2026-04-02T20:16:19Z"
severities:
  - critical
tags:
  - authentication bypass
  - cve-2024-14034
  - hieos
  - ics
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2024-14034
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-14034
  - https://assets.belden.com/m/7ec5c6da25ef288/original/Belden_Security_Bulletin_BSECV-2024-02_1v0.pdf
rules:
  - title: Detect Suspicious HiEOS Management Requests
    description: Detects suspicious HTTP requests to the HiEOS management interface that may indicate an attempted authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect HiEOS Configuration Download
    description: Detects HTTP GET requests to download the HiEOS configuration file, which could indicate unauthorized access.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2024-14034 describes an authentication bypass vulnerability affecting Hirschmann HiEOS devices. The vulnerability resides within the HTTP(S) management module and allows unauthenticated remote attackers to gain administrative privileges. By sending specially crafted HTTP(S) requests, attackers can bypass authentication checks due to improper handling. This enables them to perform unauthorized actions such as downloading or uploading device configurations and modifying the device firmware…
