---
title: Amazon Athena ODBC Driver Authentication Bypass Vulnerability (CVE-2026-35561)
slug: 2026-04-amazon-athena-auth-bypass
description: CVE-2026-35561 describes an insufficient authentication security control vulnerability in the browser-based authentication components of the Amazon Athena ODBC driver before version 2.1.0.0, potentially allowing a threat actor to intercept or hijack authentication sessions.
date: "2026-04-03T21:17:12Z"
severities:
  - high
tags:
  - amazon
  - athena
  - odbc
  - authentication
  - hijacking
  - cve-2026-35561
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1185
    technique_name: Drive-by Compromise
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
cves:
  - id: CVE-2026-35561
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35561
  - https://aws.amazon.com/security/security-bulletins/2026-013-aws/
  - https://docs.aws.amazon.com/athena/latest/ug/odbc-v2-driver-release-notes.html
rules:
  - title: Detect Suspicious Athena ODBC Driver User Agent
    description: Detects connections using older, vulnerable Amazon Athena ODBC driver versions based on the User-Agent string.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Network Connection from Amazon Athena ODBC Driver
    description: Detects network connections from the Amazon Athena ODBC driver to unusual or unexpected destinations, potentially indicating compromised credentials or session hijacking.
    platform: sigma
    severity: low
    tactics:
      - lateral_movement
    techniques:
      - T1021.002
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2026-35561 identifies a critical vulnerability within the Amazon Athena ODBC driver, specifically affecting versions prior to 2.1.0.0. This flaw resides in the browser-based authentication components, where insufficient security controls could enable attackers to intercept or hijack legitimate authentication sessions. The vulnerability stems from inadequate protection mechanisms within the authentication flows, leaving users susceptible to unauthorized access. To mitigate this risk, Amazon…
