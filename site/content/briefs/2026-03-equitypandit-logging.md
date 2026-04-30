---
title: EquityPandit 1.0 Insecure Logging Vulnerability (CVE-2019-25605)
slug: 2026-03-equitypandit-logging
description: EquityPandit 1.0 contains an insecure logging vulnerability (CVE-2019-25605) that allows attackers to capture sensitive user credentials by accessing developer console logs via Android Debug Bridge, specifically exposing plaintext passwords during the forgot password function.
date: "2026-03-23T14:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - insecure-logging
  - credential-access
  - android
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25605
  - https://www.exploit-db.com/exploits/46933
  - https://www.vulncheck.com/advisories/equitypandit-insecure-logging-information-disclosure
rules:
  - title: Detect ADB Logcat Usage
    description: Detects the use of adb logcat command, often used to extract sensitive information from Android devices.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Network Connection to ADB Port
    description: Detects connections to the standard ADB port (5555).
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

EquityPandit 1.0, an Android application, is vulnerable to insecure logging practices. Specifically, the application logs sensitive user credentials, including plaintext passwords, within the developer console logs. This vulnerability, identified as CVE-2019-25605, allows an attacker with access to the device or ADB (Android Debug Bridge) to extract these credentials. The vulnerability was reported in 2019, but publicly disclosed details and exploits surfaced more recently. Successful…
