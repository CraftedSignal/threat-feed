---
title: Edimax EW-7438RPn Stack-Based Buffer Overflow (CVE-2026-9348)
slug: 2026-05-edimax-buffer-overflow
description: A stack-based buffer overflow vulnerability (CVE-2026-9348) exists in Edimax EW-7438RPn devices up to version 1.31, allowing remote attackers to execute arbitrary code by manipulating the 'webs' argument in the /goform/mp file.
date: "2026-05-26T13:44:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-9348
  - buffer overflow
  - edimax
  - stack overflow
vendors:
  - Edimax
products:
  - EW-7438RPn
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-9348
    cvss: 8.8
    epss: 0.00041
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9348
  - https://github.com/wudipjq/my_vuln/blob/main/Edimax/vuln_6/6.md
  - https://vuldb.com/submit/813890
  - https://vuldb.com/vuln/365311
  - https://vuldb.com/vuln/365311/cti
rules:
  - title: Detect CVE-2026-9348 Exploitation Attempt - Edimax Buffer Overflow
    description: Detects CVE-2026-9348 exploitation attempt — HTTP request to /goform/mp with a very long webs parameter indicating a buffer overflow attempt
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9348 Likely Exploit Payload in webs Parameter
    description: Detects CVE-2026-9348 exploitation attempt — presence of shell metacharacters or common exploit techniques within the 'webs' parameter of a request to /goform/mp, indicating a possible exploit attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A stack-based buffer overflow vulnerability, tracked as CVE-2026-9348, has been discovered in Edimax EW-7438RPn devices up to version 1.31. This vulnerability resides within the 'webs' component, specifically in the `/goform/mp` file. By manipulating the 'webs' argument, a remote attacker can trigger a buffer overflow, potentially leading to arbitrary code execution. The vendor was notified about the vulnerability, but did not respond. Publicly available exploit code exists, increasing the likelihood of exploitation. This vulnerability poses a significant risk to users of the affected Edimax devices, potentially allowing attackers to gain full control of the device and compromise the network it is connected to.

## Attack Chain

1.  The attacker identifies an Edimax EW-7438RPn device running a vulnerable firmware version (<= 1.31).
2.  The attacker crafts a malicious HTTP request targeting the `/goform/mp` endpoint.
3.  The malicious request includes an overly long string in the `webs` parameter, designed to overflow the stack buffer.
4.  The device's web server (webs component) processes the crafted request without proper bounds checking on the `webs` argument.
5.  The overflow overwrites critical data on the stack, including the return address.
6.  Upon returning from the function handling the request, the execution flow is redirected to an address controlled by the attacker.
7.  The attacker gains arbitrary code execution on the device.
8.  The attacker can then use this access to install malware, exfiltrate data, or pivot to other devices on the network.

## Impact

Successful exploitation of this buffer overflow vulnerability (CVE-2026-9348) allows a remote attacker to gain complete control of the Edimax EW-7438RPn device. This can lead to a variety of malicious activities, including data theft, device hijacking, and network compromise. Given the widespread use of these devices in home and small business networks, a successful attack could impact a large number of users.

## Recommendation

*   Deploy the Sigma rule "Detect CVE-2026-9348 Exploitation Attempt - Edimax Buffer Overflow" to identify exploitation attempts targeting the vulnerable `/goform/mp` endpoint.
*   Apply the Sigma rule "Detect CVE-2026-9348 Likely Exploit Payload in webs Parameter" to detect shell metacharacters and other exploit attempts in the webs parameter.
*   Monitor web server logs for suspicious activity related to the `/goform/mp` endpoint.
