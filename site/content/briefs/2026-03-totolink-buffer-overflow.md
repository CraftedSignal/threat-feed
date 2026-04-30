---
title: Totolink LR350 Remote Buffer Overflow Vulnerability (CVE-2026-4976)
slug: 2026-03-totolink-buffer-overflow
description: A buffer overflow vulnerability in Totolink LR350 version 9.3.5u.6369_B20220309 allows a remote attacker to execute arbitrary code by manipulating the 'ssid' argument in the setWiFiGuestCfg function.
date: "2026-03-27T21:17:28Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-4976
  - buffer-overflow
  - totolink
  - router
  - remote-code-execution
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4976
  - https://lavender-bicycle-a5a.notion.site/TOTOLINK-LR350-setWiFiGuestCfg-32153a41781f8048a918c1c78e95064e?source=copy_link
  - https://vuldb.com/?ctiid.353863
  - https://vuldb.com/?id.353863
  - https://vuldb.com/?submit.778274
  - https://www.totolink.net/
rules:
  - title: Detect Suspiciously Long SSID Parameter in Totolink CGI Request
    description: Detects HTTP POST requests to cstecgi.cgi with an abnormally long SSID parameter, indicating a potential buffer overflow attempt in Totolink LR350.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Attempts to Access Totolink Configuration CGI
    description: Detects access attempts to the Totolink configuration CGI, which may indicate reconnaissance or exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical buffer overflow vulnerability, CVE-2026-4976, has been identified in Totolink LR350 routers running firmware version 9.3.5u.6369_B20220309. The vulnerability resides in the `setWiFiGuestCfg` function within the `/cgi-bin/cstecgi.cgi` file. By crafting a malicious HTTP request and manipulating the `ssid` argument, a remote, unauthenticated attacker can trigger a buffer overflow, potentially leading to arbitrary code execution on the device. The availability of a public exploit…
