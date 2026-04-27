---
title: TOTOLINK A7000R Stack-Based Buffer Overflow Vulnerability
slug: 2026-04-totolink-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-6168) exists in TOTOLINK A7000R devices up to version 9.1.0u.6115, allowing remote attackers to execute arbitrary code via a crafted ssid5g argument to the setWiFiEasyGuestCfg function in /cgi-bin/cstecgi.cgi.
date: "2026-04-13T07:16:51Z"
severities:
  - critical
tags:
  - totolink
  - buffer-overflow
  - cve-2026-6168
  - router
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-6168
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-6168
  - https://github.com/zhuchan770/vulnerability/blob/main/A7000R/setWiFiEasyGuestCfg/ToToLink%20A7000R%20setWiFiEasyGuestCfg%20338996b67c9780b89829d0ea70058788.md
  - https://vuldb.com/vuln/357056
rules:
  - title: Detect Suspiciously Long SSID in TOTOLINK Web Requests
    description: Detects abnormally long SSID values in POST requests to cstecgi.cgi, potentially indicating a buffer overflow attempt on TOTOLINK devices.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Access to TOTOLINK CGI Binaries
    description: Detects access to common TOTOLINK CGI binaries which may indicate vulnerability scanning or exploitation attempts
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A stack-based buffer overflow vulnerability, tracked as CVE-2026-6168, has been identified in TOTOLINK A7000R routers with firmware versions up to 9.1.0u.6115. The vulnerability resides within the `setWiFiEasyGuestCfg` function located in the `/cgi-bin/cstecgi.cgi` file. Successful exploitation allows a remote attacker to execute arbitrary code on the device. Publicly available exploit code exists, increasing the risk of widespread exploitation. Given the widespread use of TOTOLINK devices…
