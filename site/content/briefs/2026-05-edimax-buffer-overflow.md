---
title: Edimax BR-6675nD Buffer Overflow Vulnerability (CVE-2026-9399)
slug: 2026-05-edimax-buffer-overflow
description: Edimax BR-6675nD version 1.12 is vulnerable to a remote buffer overflow in the formsetPPPoE function of the /goform/formsetPPPoE file due to manipulation of the pppUserName argument, allowing for remote code execution.
date: "2026-05-26T14:05:58Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - buffer-overflow
  - remote-code-execution
  - cve
vendors:
  - Edimax
products:
  - BR-6675nD 1.12
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-9399
    cvss: 8.8
    epss: 0.00041
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9399
  - https://lavender-bicycle-a5a.notion.site/EDIMAX-BR-6675nD-formsetPPPoE-34b53a41781f8025abcded9e7d0734ef?source=copy_link
  - https://vuldb.com/submit/811561
  - https://vuldb.com/vuln/365380
  - https://vuldb.com/vuln/365380/cti
rules:
  - title: Detect CVE-2026-9399 Exploitation Attempt
    description: Detects CVE-2026-9399 exploitation attempt — HTTP POST request to /goform/formsetPPPoE with a long pppUserName value indicating potential buffer overflow.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 1
---

A buffer overflow vulnerability, CVE-2026-9399, has been identified in Edimax BR-6675nD version 1.12. The vulnerability resides in the `formsetPPPoE` function within the `/goform/formsetPPPoE` file, which handles POST requests. An attacker can exploit this vulnerability by manipulating the `pppUserName` argument, causing a buffer overflow that could lead to arbitrary code execution. The exploit is publicly available, increasing the risk of exploitation. The vendor was notified but has not responded. This vulnerability poses a significant threat to devices running the affected firmware version, potentially allowing attackers to gain unauthorized access and control of the device.

## Attack Chain

1.  Attacker identifies an Edimax BR-6675nD router running firmware version 1.12.
2.  Attacker sends a crafted HTTP POST request to `/goform/formsetPPPoE`.
3.  The POST request includes the `pppUserName` parameter with a value exceeding the expected buffer size.
4.  The `formsetPPPoE` function processes the `pppUserName` argument without proper bounds checking.
5.  The oversized `pppUserName` value overflows the buffer on the stack.
6.  The buffer overflow overwrites critical data, potentially including the return address.
7.  The overwritten return address redirects execution to attacker-controlled code.
8.  Attacker gains remote code execution on the router, potentially leading to full system compromise.

## Impact

Successful exploitation of CVE-2026-9399 can allow a remote attacker to execute arbitrary code on the vulnerable Edimax BR-6675nD router. This could lead to complete compromise of the device, allowing the attacker to eavesdrop on network traffic, modify router settings, or use the router as a pivot point for further attacks within the network. Given that the exploit is public, the risk of widespread exploitation is high.

## Recommendation

*   Deploy the Sigma rule "Detect CVE-2026-9399 Exploitation Attempt" to your SIEM and tune for your environment.
*   Monitor web server logs for POST requests to `/goform/formsetPPPoE` with abnormally long `pppUserName` values, as indicated by the Sigma rule.
*   Apply any available patches or firmware updates from Edimax to address CVE-2026-9399.
*   Implement network segmentation to limit the impact of a compromised router on other network segments.
