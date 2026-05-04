---
title: Totolink WA300 Buffer Overflow Vulnerability (CVE-2026-7719)
slug: 2024-01-totolink-wa300-buffer-overflow
description: A buffer overflow vulnerability exists in Totolink WA300 version 5.2cu.7112_B20190227 within the loginauth function of the /cgi-bin/cstecgi.cgi file, specifically affecting the POST Request Handler component, triggerable via manipulation of the http_host argument, and remotely exploitable with a publicly available exploit.
date: "2026-05-04T02:15:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - buffer overflow
  - remote code execution
  - cve-2026-7719
  - totolink
vendors:
  - Totolink
products:
  - WA300 5.2cu.7112_B20190227
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7719
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7719
rules:
  - title: Detect Totolink WA300 HTTP Host Buffer Overflow Attempt
    description: Detects potential attempts to exploit the CVE-2026-7719 buffer overflow vulnerability in Totolink WA300 devices by monitoring for unusually long http_host headers in POST requests to the cstecgi.cgi endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Totolink WA300 LoginAuth Access
    description: Detects access to the loginauth function which is the vulnerable component in Totolink WA300.
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

A critical buffer overflow vulnerability, identified as CVE-2026-7719, has been discovered in Totolink WA300 version 5.2cu.7112_B20190227. This vulnerability resides within the `loginauth` function of the `/cgi-bin/cstecgi.cgi` file, affecting the POST Request Handler component. The vulnerability is triggered by manipulating the `http_host` argument in a POST request. The exploit is publicly available, increasing the risk of widespread exploitation. This vulnerability allows for remote code execution, potentially granting attackers full control over the affected device. The affected version was released in February 2019. Defenders should prioritize patching or mitigating this vulnerability to prevent potential compromise.

## Attack Chain

1.  The attacker identifies a vulnerable Totolink WA300 device running firmware version 5.2cu.7112_B20190227.
2.  The attacker crafts a malicious HTTP POST request targeting the `/cgi-bin/cstecgi.cgi` endpoint.
3.  The crafted POST request includes a specially crafted `http_host` argument designed to overflow the buffer in the `loginauth` function.
4.  The vulnerable `loginauth` function processes the `http_host` argument without proper bounds checking.
5.  The oversized `http_host` argument overwrites adjacent memory regions, including the return address on the stack.
6.  Upon completion of the `loginauth` function, the overwritten return address is used, redirecting execution to attacker-controlled code.
7.  The attacker-controlled code executes with elevated privileges, allowing the attacker to execute arbitrary commands on the device.
8.  The attacker gains complete control of the device, potentially using it for malicious purposes such as botnet participation, data theft, or further network penetration.

## Impact

Successful exploitation of CVE-2026-7719 allows a remote attacker to execute arbitrary code on the vulnerable Totolink WA300 device. This can lead to complete device compromise, allowing the attacker to steal sensitive information, use the device as a botnet node, or pivot to other devices on the network. Given the public availability of the exploit, widespread exploitation is possible, potentially affecting a large number of home and small business networks using the vulnerable device.

## Recommendation

*   Deploy the Sigma rule `Detect Totolink WA300 HTTP Host Buffer Overflow Attempt` to identify exploitation attempts in web server logs.
*   Monitor web server logs for POST requests to `/cgi-bin/cstecgi.cgi` with unusually long `http_host` headers.
*   Consider deploying a web application firewall (WAF) rule to filter out malicious requests targeting CVE-2026-7719.
*   Upgrade to a patched version of the firmware or replace the affected device to remediate the vulnerability.
