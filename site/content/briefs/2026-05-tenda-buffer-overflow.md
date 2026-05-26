---
title: Tenda F1202 Stack-Based Buffer Overflow Vulnerability (CVE-2026-9431)
slug: 2026-05-tenda-buffer-overflow
description: A remote stack-based buffer overflow vulnerability (CVE-2026-9431) exists in the fromPptpUserAdd function of the /goform/PptpUserAdd file in Tenda F1202 firmware version 1.2.0.20(408), allowing unauthenticated attackers to potentially execute arbitrary code.
date: "2026-05-26T14:10:28Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - cve
  - buffer-overflow
  - tenda
  - router
  - rce
vendors:
  - Tenda
products:
  - F1202 1.2.0.20(408)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-9431
    cvss: 8.8
    epss: 0.00046
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9431
  - https://github.com/Litengzheng/vuldb_new2/blob/main/F1202/vul_35/README.md
  - https://vuldb.com/submit/813916
  - https://vuldb.com/vuln/365412
  - https://vuldb.com/vuln/365412/cti
  - https://www.tenda.com.cn/
rules:
  - title: Detect Tenda F1202 Buffer Overflow Attempt
    description: Detects CVE-2026-9431 exploitation — attempts to exploit the stack-based buffer overflow in Tenda F1202 via a long opttype parameter in a POST request to /goform/PptpUserAdd.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
  - title: Detect Tenda F1202 Goform Directory Access
    description: Detects access to the /goform directory on Tenda F1202 devices, which is often targeted by exploit attempts.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

A stack-based buffer overflow vulnerability, CVE-2026-9431, has been identified in Tenda F1202 router firmware version 1.2.0.20(408). The vulnerability resides in the `fromPptpUserAdd` function within the `/goform/PptpUserAdd` file. By manipulating the `opttype` argument, an attacker can trigger a buffer overflow, potentially leading to arbitrary code execution on the device. This vulnerability can be exploited remotely without authentication. Publicly available exploit code exists, increasing the risk of exploitation in the wild. This issue poses a significant threat to network security, potentially allowing attackers to gain control of vulnerable devices.

## Attack Chain

1.  Attacker identifies a Tenda F1202 router running firmware version 1.2.0.20(408).
2.  Attacker sends a crafted HTTP POST request to the `/goform/PptpUserAdd` endpoint.
3.  The POST request includes the `opttype` argument with a value exceeding the buffer size allocated in the `fromPptpUserAdd` function.
4.  The `fromPptpUserAdd` function processes the malicious `opttype` argument without proper bounds checking.
5.  The oversized `opttype` value overflows the stack buffer, overwriting adjacent memory locations.
6.  The attacker crafts the overflow to overwrite the return address on the stack, redirecting execution flow.
7.  The overwritten return address points to attacker-controlled code, which is injected into the overflow.
8.  The attacker-controlled code executes with the privileges of the `fromPptpUserAdd` function, allowing the attacker to execute arbitrary commands on the router.

## Impact

Successful exploitation of CVE-2026-9431 allows a remote, unauthenticated attacker to execute arbitrary code on the Tenda F1202 router. This can lead to complete device compromise, including modification of router settings, interception of network traffic, and use of the router as a botnet node. Given the publicly available exploit code, widespread exploitation is possible, potentially impacting numerous home and small business networks using the vulnerable Tenda F1202 model.

## Recommendation

*   Monitor web server logs for suspicious POST requests to `/goform/PptpUserAdd` with unusually long `opttype` values to detect potential exploitation attempts.
*   Deploy the Sigma rule `Detect Tenda F1202 Buffer Overflow Attempt` to your SIEM to identify suspicious requests.
*   Consider deploying a web application firewall (WAF) rule to block requests with excessively long `opttype` values sent to `/goform/PptpUserAdd`.
