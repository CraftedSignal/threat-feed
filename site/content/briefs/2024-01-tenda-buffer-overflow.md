---
title: Tenda F451 Stack-Based Buffer Overflow Vulnerability (CVE-2026-5992)
slug: 2024-01-tenda-buffer-overflow
description: Tenda F451 version 1.0.0.7 is vulnerable to a stack-based buffer overflow in the fromP2pListFilter function, allowing remote attackers to execute arbitrary code by manipulating the 'page' argument in the /goform/P2pListFilter file.
date: "2024-01-23T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - tenda
  - buffer-overflow
  - cve-2026-5992
vendors:
  - Tenda
products:
  - F451
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5992
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5992
  - https://github.com/Jimi-Lab/cve/issues/10
  - https://vuldb.com/vuln/356546
rules:
  - title: Tenda F451 P2P Filter Buffer Overflow Attempt
    description: Detects attempts to exploit the stack-based buffer overflow vulnerability (CVE-2026-5992) in the Tenda F451 router by monitoring HTTP requests to the /goform/P2pListFilter endpoint with overly long 'page' parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1071.001
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Tenda F451 Unauthorized Access to P2P Filter
    description: Detects unauthorized attempts to access the P2P filter configuration page on Tenda F451 routers, which may indicate reconnaissance or exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-5992 is a critical stack-based buffer overflow vulnerability affecting Tenda F451 version 1.0.0.7. The vulnerability resides within the `fromP2pListFilter` function of the `/goform/P2pListFilter` file. Attackers can remotely exploit this flaw by manipulating the `page` argument, potentially leading to arbitrary code execution. Publicly available exploits exist, increasing the likelihood of exploitation. Given the prevalence of Tenda routers and the ease of remote exploitation, this vulnerability poses a significant risk to home and small business networks. Successful exploitation could allow attackers to gain complete control of the affected device, leading to data theft, network compromise, and potential use in botnet activities. Defenders should prioritize detection and mitigation efforts to prevent exploitation.

## Attack Chain

1.  The attacker identifies a vulnerable Tenda F451 router running firmware version 1.0.0.7.
2.  The attacker crafts a malicious HTTP request targeting the `/goform/P2pListFilter` endpoint.
3.  The crafted request includes a `page` argument with a payload exceeding the buffer size allocated for it in the `fromP2pListFilter` function.
4.  The router processes the malicious HTTP request, triggering the stack-based buffer overflow within the `fromP2pListFilter` function due to insufficient bounds checking on the `page` argument.
5.  The overflow overwrites adjacent memory regions on the stack, including the return address.
6.  When the `fromP2pListFilter` function returns, it jumps to the address overwritten by the attacker-controlled payload.
7.  The attacker-controlled payload executes arbitrary code on the router, such as downloading and executing a malicious binary from a remote server or modifying router configuration.
8.  The attacker gains complete control of the router, enabling them to perform malicious activities such as eavesdropping on network traffic, modifying DNS settings, or using the router as part of a botnet.

## Impact

Successful exploitation of CVE-2026-5992 allows remote attackers to gain complete control of vulnerable Tenda F451 routers. This can lead to a variety of malicious activities, including data theft, network compromise, and botnet recruitment. Given the widespread use of Tenda routers, a large number of devices are potentially at risk. If attackers successfully exploit this vulnerability, they can perform man-in-the-middle attacks, redirect users to malicious websites, and compromise connected devices on the network.

## Recommendation

*   Monitor web server logs for HTTP requests targeting the `/goform/P2pListFilter` endpoint with unusually long `page` parameters to detect potential exploitation attempts. Use the Sigma rule `Tenda F451 P2P Filter Buffer Overflow Attempt` to identify this behavior.
*   Deploy network intrusion detection systems (IDS) rules to detect exploitation attempts targeting CVE-2026-5992.
*   Unfortunately, there is no patch available as of this writing, and the device is end-of-life. Consider replacing the affected device.
