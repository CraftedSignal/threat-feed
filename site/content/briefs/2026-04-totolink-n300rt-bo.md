---
title: Totolink N300RT Buffer Overflow Vulnerability (CVE-2026-7219)
slug: 2026-04-totolink-n300rt-bo
description: A remote buffer overflow vulnerability exists in Totolink N300RT 3.4.0-B20250430 via manipulation of the 'entry_name' argument in the /boafrm/formIpQoS file, potentially leading to arbitrary code execution.
date: "2026-04-28T04:16:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - buffer-overflow
  - iot
  - router
  - cve-2026-7219
vendors:
  - Totolink
products:
  - N300RT
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7219
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7219
  - https://github.com/xiaohaiyang-ai/IoT-Vulnerability-Research/tree/main/Vendors/TOTOLINK/N300RT/formIpQoS-Bof
  - https://vuldb.com/vuln/359819
rules:
  - title: Detect Suspicious Totolink FormIpQoS Requests
    description: Detects abnormally large POST requests to the /boafrm/formIpQoS endpoint which may indicate a buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Large POST Requests to Router Config Pages
    description: Detects suspiciously large POST requests to common router configuration pages.  This can indicate exploitation attempts.
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

A buffer overflow vulnerability, identified as CVE-2026-7219, has been discovered in Totolink N300RT router firmware version 3.4.0-B20250430. The vulnerability resides within the `/boafrm/formIpQoS` file and is triggered by manipulating the `entry_name` argument. An attacker can exploit this flaw remotely to potentially execute arbitrary code on the device. Publicly available exploit code exists, increasing the risk of exploitation. This vulnerability poses a significant threat to devices running the affected firmware, potentially allowing attackers to gain unauthorized access and control over the router.

## Attack Chain

1. An attacker identifies a Totolink N300RT device running firmware version 3.4.0-B20250430.
2. The attacker crafts a malicious HTTP request targeting the `/boafrm/formIpQoS` file.
3. The crafted request includes a payload designed to overflow the buffer associated with the `entry_name` argument.
4. The router's web server processes the malicious request, leading to a buffer overflow condition.
5. The attacker overwrites adjacent memory regions, potentially including return addresses or other critical data.
6. Upon function return, the overwritten return address is used, diverting execution flow to attacker-controlled code.
7. The attacker gains arbitrary code execution on the device.
8. The attacker can then use this access to modify router settings, intercept network traffic, or establish a persistent backdoor.

## Impact

Successful exploitation of this vulnerability allows a remote attacker to execute arbitrary code on the Totolink N300RT device. This could lead to complete compromise of the router, enabling attackers to monitor network traffic, change DNS settings, or use the device as part of a botnet. Given the number of Totolink N300RT devices deployed, this vulnerability could have a widespread impact, especially for home and small business users.

## Recommendation

*   Monitor web server logs for requests targeting `/boafrm/formIpQoS` with unusually long `entry_name` parameters to detect potential exploitation attempts. Implement the Sigma rule `Detect Suspicious Totolink FormIpQoS Requests`.
*   Apply firmware updates as soon as they are released by Totolink to patch CVE-2026-7219.
*   Implement network segmentation to limit the impact of a compromised router on other devices on the network.
*   Consider using a web application firewall (WAF) to filter out malicious requests targeting the router's web interface and activate the `Detect Large POST Requests to Router Config Pages` Sigma rule.
