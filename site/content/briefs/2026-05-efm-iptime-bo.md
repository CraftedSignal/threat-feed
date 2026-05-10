---
title: EFM ipTIME A8004T Stack-Based Buffer Overflow (CVE-2026-8234)
slug: 2026-05-efm-iptime-bo
description: A stack-based buffer overflow vulnerability (CVE-2026-8234) exists in EFM ipTIME A8004T version 14.18.2, allowing remote attackers to execute arbitrary code by manipulating the security_5g argument in the formWifiBasicSet function.
date: "2026-05-10T07:16:08Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - cve
  - buffer overflow
  - router
  - rce
vendors:
  - EFM
products:
  - ipTIME A8004T 14.18.2
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-8234
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8234
  - https://github.com/Kiciot/cve/issues/5
  - https://vuldb.com/submit/808865
  - https://vuldb.com/vuln/362454
  - https://vuldb.com/vuln/362454/cti
rules:
  - title: Detect CVE-2026-8234 Exploitation Attempt
    description: Detects CVE-2026-8234 exploitation attempt — HTTP request to WifiBasicSet with an overly long security_5g parameter indicating a stack buffer overflow attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A stack-based buffer overflow vulnerability, identified as CVE-2026-8234, has been discovered in EFM ipTIME A8004T version 14.18.2. The vulnerability resides within the `formWifiBasicSet` function in the `/goform/WifiBasicSet` file. By manipulating the `security_5g` argument, a remote attacker can trigger a buffer overflow, potentially leading to arbitrary code execution. This vulnerability was publicly disclosed, and an exploit is available. The vendor was notified but did not respond. This issue poses a significant risk to users of the affected device, as it can be exploited remotely without requiring authentication after successful exploitation.

## Attack Chain

1.  The attacker identifies an EFM ipTIME A8004T router running firmware version 14.18.2 with the vulnerable `formWifiBasicSet` function.
2.  The attacker crafts a malicious HTTP request targeting the `/goform/WifiBasicSet` endpoint.
3.  Within the HTTP request, the attacker includes a specially crafted `security_5g` argument designed to overflow the buffer allocated in the `formWifiBasicSet` function.
4.  The router processes the HTTP request and calls the `formWifiBasicSet` function with the attacker-controlled `security_5g` argument.
5.  The `formWifiBasicSet` function copies the attacker-supplied data from the `security_5g` argument into a fixed-size buffer on the stack without proper bounds checking.
6.  The copied data exceeds the buffer's capacity, overwriting adjacent memory regions on the stack.
7.  The attacker carefully crafts the overflow to overwrite the return address on the stack with the address of malicious code.
8.  When the `formWifiBasicSet` function returns, it jumps to the attacker-controlled address, executing arbitrary code on the router.

## Impact

Successful exploitation of CVE-2026-8234 allows a remote attacker to execute arbitrary code on the affected EFM ipTIME A8004T router. This could lead to complete compromise of the device, including the ability to intercept network traffic, modify router settings, or use the device as a pivot point for further attacks within the network. Given the public availability of an exploit, there is a high risk of widespread exploitation.

## Recommendation

*   Monitor web server logs for requests to `/goform/WifiBasicSet` with abnormally long `security_5g` parameters to detect potential exploitation attempts. Deploy the Sigma rule `Detect CVE-2026-8234 Exploitation Attempt` to identify malicious requests.
*   Implement rate limiting for requests to `/goform/WifiBasicSet` to mitigate potential brute-force exploitation attempts.
*   Since no patch is available, consider replacing the affected EFM ipTIME A8004T routers with devices from vendors who provide security updates, especially if those devices are exposed to the internet.
