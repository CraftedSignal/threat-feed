---
title: Totolink N300RH Remote Buffer Overflow Vulnerability
slug: 2026-05-totolink-buffer-overflow
description: A buffer overflow vulnerability exists in Totolink N300RH version 3.2.4-B20220812 within the loginauth function of the /cgi-bin/cstecgi.cgi file, allowing a remote attacker to potentially execute arbitrary code by manipulating the Password argument.
date: "2026-05-04T09:16:01Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - buffer overflow
  - router vulnerability
  - remote code execution
vendors:
  - Totolink
products:
  - N300RH 3.2.4-B20220812
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7747
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7747
  - https://lavender-bicycle-a5a.notion.site/TOTOLINK-N300RH-loginauth_password-34553a41781f80c0ad36f4d95122fd40?pvs=73
  - https://vuldb.com/vuln/360922
rules:
  - title: Detect Totolink N300RH CVE-2026-7747 Exploit Attempt
    description: Detects attempts to exploit the CVE-2026-7747 buffer overflow vulnerability in Totolink N300RH routers by monitoring for abnormally long password parameters in POST requests to the /cgi-bin/cstecgi.cgi endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink N300RH CVE-2026-7747 Exploit Response
    description: Detects hosts communicating with a potentially compromised Totolink N300RH router after a successful exploit.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-7747, affects Totolink N300RH router version 3.2.4-B20220812. The vulnerability resides within the loginauth function of the `/cgi-bin/cstecgi.cgi` file, specifically in the Parameter Handler component. A remote attacker can exploit this vulnerability by sending a crafted request manipulating the `Password` argument, leading to a buffer overflow condition. Publicly available exploits exist, increasing the risk of active exploitation. Successful exploitation could grant the attacker unauthorized control over the affected device.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink N300RH router with firmware version 3.2.4-B20220812 exposed to the internet.
2.  The attacker crafts a malicious HTTP request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The malicious request includes a `Password` argument exceeding the expected buffer size in the `loginauth` function.
4.  The router's web server processes the crafted request and passes the oversized `Password` argument to the vulnerable function.
5.  The `loginauth` function fails to properly validate the input length, leading to a buffer overflow.
6.  The buffer overflow overwrites adjacent memory regions, potentially including critical program data or execution pointers.
7.  The attacker gains control of the program execution flow, enabling the execution of arbitrary code.
8.  The attacker establishes a reverse shell or modifies the router's configuration to gain persistent access and control of the device.

## Impact

Successful exploitation of CVE-2026-7747 allows an attacker to execute arbitrary code on the affected Totolink N300RH router. This could lead to complete device compromise, allowing the attacker to intercept network traffic, modify router settings, or use the device as part of a botnet. Given the widespread use of Totolink routers, a successful attack could potentially impact a large number of home and small business networks.

## Recommendation

*   Monitor network traffic for suspicious POST requests to `/cgi-bin/cstecgi.cgi` with abnormally long `Password` parameters to detect potential exploit attempts, as covered by the Sigma rule "Detect Totolink N300RH CVE-2026-7747 Exploit Attempt".
*   Implement rate limiting on login attempts to the web interface to mitigate brute-force attacks potentially combined with the buffer overflow.
*   Apply any available firmware updates from Totolink to patch CVE-2026-7747, if a patch is released in the future.
*   Deploy the Sigma rule "Detect Totolink N300RH CVE-2026-7747 Exploit Response" to identify systems communicating with potentially compromised Totolink devices.
