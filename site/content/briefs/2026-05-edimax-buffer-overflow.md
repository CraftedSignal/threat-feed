---
title: Edimax EW-7438RPn Buffer Overflow Vulnerability (CVE-2026-9346)
slug: 2026-05-edimax-buffer-overflow
description: A remote buffer overflow vulnerability (CVE-2026-9346) exists in the formWirelessTbl function of the /goform/formWirelessTbl file in Edimax EW-7438RPn devices up to version 1.31, allowing attackers to execute arbitrary code by manipulating the submit-url argument.
date: "2026-05-26T14:05:45Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - buffer overflow
  - remote code execution
  - cve-2026-9346
vendors:
  - Edimax
products:
  - EW-7438RPn
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-9346
    cvss: 8.8
    epss: 0.00043
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9346
  - https://github.com/wudipjq/my_vuln/blob/main/Edimax/vuln_4/4.md
  - https://vuldb.com/submit/811541
  - https://vuldb.com/submit/813888
  - https://vuldb.com/vuln/365309
  - https://vuldb.com/vuln/365309/cti
rules:
  - title: Detect CVE-2026-9346 Exploitation Attempt — Long submit-url Parameter
    description: Detects CVE-2026-9346 exploitation attempts by monitoring for abnormally long submit-url parameters in POST requests to /goform/formWirelessTbl
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-9346 Exploitation Attempt — Shell Metacharacters in submit-url
    description: Detects CVE-2026-9346 exploitation attempts by monitoring for shell metacharacters in the submit-url parameter.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-9346, affects Edimax EW-7438RPn devices with firmware versions up to 1.31. This vulnerability is located within the webs component, specifically in the formWirelessTbl function of the /goform/formWirelessTbl file. An attacker can exploit this flaw remotely by crafting a malicious request containing a manipulated submit-url argument. Successful exploitation of this vulnerability could lead to arbitrary code execution on the affected device. The vulnerability was reported to the vendor, but they did not respond. Public exploit code is available, increasing the risk of exploitation.

## Attack Chain

1.  The attacker identifies an Edimax EW-7438RPn device running firmware version 1.31 or earlier.
2.  The attacker crafts a malicious HTTP request targeting the `/goform/formWirelessTbl` endpoint.
3.  The attacker includes a `submit-url` argument within the HTTP request, injecting a string exceeding the expected buffer size.
4.  The web server processes the request and calls the `formWirelessTbl` function.
5.  The `formWirelessTbl` function copies the attacker-controlled `submit-url` argument into a fixed-size buffer without proper bounds checking.
6.  The buffer overflow overwrites adjacent memory regions, potentially including function return addresses.
7.  The attacker gains control of the program execution flow when the function returns.
8.  The attacker executes arbitrary code on the device, potentially gaining full control.

## Impact

Successful exploitation of CVE-2026-9346 allows a remote attacker to execute arbitrary code on the Edimax EW-7438RPn device. This can lead to complete compromise of the device, allowing the attacker to eavesdrop on network traffic, modify device settings, or use the device as a foothold for further attacks within the network. Given the lack of vendor response, many devices may remain vulnerable indefinitely.

## Recommendation

*   Inspect webserver logs for HTTP POST requests to `/goform/formWirelessTbl` with abnormally long `submit-url` parameters to detect exploitation attempts. Deploy the Sigma rule `Detect CVE-2026-9346 Exploitation Attempt — Long submit-url Parameter`.
*   Monitor network traffic for suspicious activity originating from Edimax EW-7438RPn devices.
*   Since no patch is available, consider replacing the Edimax EW-7438RPn devices with more secure alternatives.
