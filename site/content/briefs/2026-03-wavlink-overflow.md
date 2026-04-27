---
title: Wavlink WL-NU516U1 Stack-Based Buffer Overflow Vulnerability (CVE-2026-4861)
slug: 2026-03-wavlink-overflow
description: A stack-based buffer overflow vulnerability exists in Wavlink WL-NU516U1 version 260227, affecting the ftext function within the /cgi-bin/nas.cgi file, which can be exploited by a remote attacker manipulating the Content-Length argument, with a public exploit available.
date: "2026-03-26T09:16:06Z"
severities:
  - critical
tags:
  - cve-2026-4861
  - buffer-overflow
  - wavlink
  - network-device
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4861
  - https://github.com/Wlz1112/WAVLINK-NU516U1-V260227/blob/main/Content-Length.md
  - https://vuldb.com/?ctiid.353192
  - https://vuldb.com/?id.353192
rules:
  - title: Detect Suspicious Content-Length in NAS CGI
    description: Detects HTTP requests to /cgi-bin/nas.cgi with unusually large Content-Length headers, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP POST to NAS CGI
    description: Detects HTTP POST requests to the /cgi-bin/nas.cgi endpoint.
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

A stack-based buffer overflow vulnerability, identified as CVE-2026-4861, has been discovered in Wavlink WL-NU516U1 with firmware version 260227. The flaw resides in the `ftext` function of the `/cgi-bin/nas.cgi` file. By crafting a malicious HTTP request and manipulating the `Content-Length` argument, an attacker can trigger a buffer overflow, potentially leading to arbitrary code execution. Publicly available exploits exist, increasing the likelihood of exploitation. The vendor has been…
