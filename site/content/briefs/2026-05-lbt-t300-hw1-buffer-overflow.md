---
title: Shenzhen Libituo Technology LBT-T300-HW1 Buffer Overflow Vulnerability
slug: 2026-05-lbt-t300-hw1-buffer-overflow
description: A buffer overflow vulnerability exists in Shenzhen Libituo Technology LBT-T300-HW1 version 1.2.8 and earlier, allowing remote attackers to execute arbitrary code by manipulating the Channel/ApCliSsid argument in the start_lan function of the /apply.cgi file.
date: "2026-05-03T03:16:15Z"
type: threat
types:
  - threat
severities:
  - critical
tags:
  - buffer overflow
  - remote code execution
  - web application vulnerability
vendors:
  - Shenzhen Libituo Technology
products:
  - LBT-T300-HW1 (<= 1.2.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7675
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7675
  - https://github.com/hmKunlun/lbt-t300-hw1/blob/main/generate_conf_router(Channel).md
  - https://vuldb.com/submit/800708
  - https://vuldb.com/submit/800709
  - https://vuldb.com/vuln/360828
  - https://vuldb.com/vuln/360828/cti
rules:
  - title: Detect LBT-T300-HW1 /apply.cgi Buffer Overflow Attempt
    description: Detects attempts to exploit the buffer overflow vulnerability in Shenzhen Libituo Technology LBT-T300-HW1 devices by monitoring the length of the Channel/ApCliSsid parameter in POST requests to /apply.cgi.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect LBT-T300-HW1 /apply.cgi Access
    description: Detects access to the /apply.cgi page, which is associated with the buffer overflow vulnerability in Shenzhen Libituo Technology LBT-T300-HW1 devices. This rule detects both GET and POST requests.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-7675, affects Shenzhen Libituo Technology LBT-T300-HW1 devices with firmware versions up to 1.2.8. The vulnerability resides in the `start_lan` function within the `/apply.cgi` file. By manipulating the `Channel/ApCliSsid` argument, a remote attacker can trigger a buffer overflow, potentially leading to arbitrary code execution. Publicly available exploit code exists for this vulnerability. The vendor was notified about the vulnerability, but there has been no response. This vulnerability is considered critical due to the potential for remote exploitation and the availability of exploit code.

## Attack Chain

1.  The attacker identifies a vulnerable Shenzhen Libituo Technology LBT-T300-HW1 device running firmware version 1.2.8 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the `/apply.cgi` endpoint.
3.  The HTTP request includes a specially crafted `Channel/ApCliSsid` argument designed to overflow the buffer in the `start_lan` function.
4.  The vulnerable `start_lan` function receives the malicious input and attempts to process it without proper bounds checking.
5.  The buffer overflow occurs, overwriting adjacent memory regions, including potentially the return address on the stack.
6.  The attacker gains control of the program execution flow by overwriting the return address with the address of malicious code.
7.  The injected code executes with the privileges of the web server process.
8.  The attacker achieves arbitrary code execution, potentially gaining full control of the device.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the affected device. Given that this is a router, this could lead to complete compromise of the device, including the ability to intercept and manipulate network traffic, install malware, or use the device as part of a botnet. Due to the public availability of the exploit, widespread exploitation is possible.

## Recommendation

*   Apply network intrusion detection system (NIDS) rules to detect and block malicious HTTP requests targeting `/apply.cgi` with excessively long `Channel/ApCliSsid` values.
*   Deploy the Sigma rule `Detect-LBT-T300-HW1-applycgi-buffer-overflow` to your SIEM and tune for your environment to identify exploitation attempts.
*   Monitor web server logs for suspicious POST requests to `/apply.cgi` and analyze the length of the `Channel/ApCliSsid` parameter.
