---
title: Edimax BR-6428nC Buffer Overflow Vulnerability (CVE-2026-7684)
slug: 2026-05-edimax-br-6428nc-buffer-overflow
description: A remote buffer overflow vulnerability exists in Edimax BR-6428nC devices up to version 1.16 via manipulation of the pptpDfGateway argument in the /goform/setWAN file, potentially allowing for arbitrary code execution.
date: "2026-05-03T07:16:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - buffer overflow
  - cve-2026-7684
  - webserver
vendors:
  - Edimax
products:
  - BR-6428nC (<= 1.16)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-7684
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7684
rules:
  - title: Edimax BR-6428nC Buffer Overflow Attempt via setWAN
    description: Detects suspicious HTTP POST requests to /goform/setWAN with unusually long pptpDfGateway values, indicating a potential buffer overflow attempt.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Edimax BR-6428nC - Suspicious POST Request to setWAN
    description: This rule detects POST requests to the /goform/setWAN endpoint that contain suspicious characters often used in exploit attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A buffer overflow vulnerability, tracked as CVE-2026-7684, affects Edimax BR-6428nC devices up to version 1.16. The vulnerability resides in the `/goform/setWAN` file, specifically within the handling of the `pptpDfGateway` argument. An unauthenticated attacker can exploit this flaw remotely by sending a crafted request to the device. Publicly available exploit code exists, increasing the risk of widespread exploitation. The vendor was notified but did not respond, suggesting that a patch is unlikely and highlighting the need for mitigation strategies.

## Attack Chain

1.  The attacker identifies an Edimax BR-6428nC device running a vulnerable firmware version (<= 1.16).
2.  The attacker crafts a malicious HTTP POST request targeting the `/goform/setWAN` endpoint.
3.  The request includes the `pptpDfGateway` parameter with a value exceeding the expected buffer size.
4.  The device processes the request, and the oversized `pptpDfGateway` value overflows the buffer, overwriting adjacent memory regions.
5.  The attacker carefully crafts the overflow to overwrite the return address, redirecting execution flow.
6.  Execution is redirected to attacker-controlled code injected within the overflowed buffer.
7.  The attacker gains arbitrary code execution on the device, potentially achieving full system control.
8.  The attacker could then use this control to modify device settings, intercept network traffic, or establish a persistent backdoor.

## Impact

Successful exploitation of this vulnerability can allow an attacker to gain complete control of the Edimax BR-6428nC device. This could enable the attacker to intercept and modify network traffic, access sensitive information, or use the device as a point of entry for further attacks within the network. Given the public availability of exploit code, the risk of widespread exploitation is significant.

## Recommendation

*   Deploy the Sigma rule `Edimax_BR_6428nC_Buffer_Overflow_setWAN` to detect suspicious HTTP requests targeting the vulnerable endpoint and parameter.
*   Consider blocking or rate-limiting access to the `/goform/setWAN` endpoint from untrusted networks.
*   Since the vendor is unresponsive and a patch is unlikely, network segmentation and access control policies are the best mitigation options.
