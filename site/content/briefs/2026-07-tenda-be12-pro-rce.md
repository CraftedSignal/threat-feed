---
title: Tenda BE12 Pro Remote Code Execution Vulnerability (CVE-2026-15691)
slug: 2026-07-tenda-be12-pro-rce
description: A critical remote stack-based buffer overflow vulnerability (CVE-2026-15691) has been discovered in Tenda BE12 Pro firmware 16.03.66.23, affecting the `fromSafeClientFilter` function and allowing remote attackers to achieve arbitrary code execution by manipulating the `page` argument, with a public exploit available.
date: "2026-07-14T13:20:17Z"
lastmod: "2026-07-14T15:25:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - remote-code-execution
  - buffer-overflow
  - firmware
  - router
  - network-device
  - rce
vendors:
  - Tenda
products:
  - BE12 Pro 16.03.66.23
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A security flaw has been discovered in Tenda BE12 Pro 16.03.66.23. This affects the function fromSaf... Performing a manipulation of the argument page results in stack-based buffer overflow. The attack is possible to be carried out remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Performing a manipulation of the argument page results in stack-based buffer overflow.
    confidence_band: med
cves:
  - id: CVE-2026-15691
    cvss: 8.8
  - id: CVE-2026-15695
    cvss: 8.8
  - id: CVE-2026-15693
    cvss: 8.8
  - id: CVE-2026-15694
    cvss: 8.8
  - id: CVE-2026-15696
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15691
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15693
  - https://github.com/cve-a/dexingzhiqing/issues/3
  - https://vuldb.com/cve/CVE-2026-15693
  - https://vuldb.com/submit/856011
  - https://vuldb.com/vuln/378240
  - https://vuldb.com/vuln/378240/cti
  - https://www.tenda.com.cn/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15695
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15696
  - https://github.com/cve-a/dexingzhiqing/issues/6
  - https://vuldb.com/cve/CVE-2026-15696
  - https://vuldb.com/submit/856019
  - https://vuldb.com/vuln/378243
  - https://vuldb.com/vuln/378243/cti
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15694
iocs:
  - type: url
    value: https://github.com/cve-a/dexingzhiqing/issues/4
  - type: url
    value: https://vuldb.com/cve/CVE-2026-15694
  - type: url
    value: https://vuldb.com/submit/856015
  - type: url
    value: https://vuldb.com/vuln/378241
  - type: url
    value: https://vuldb.com/vuln/378241/cti
  - type: url
    value: https://www.tenda.com.cn/
  - type: email
    value: nvd@nist.gov
  - type: email
    value: soc@us-cert.gov
ioc_counts:
  email: 2
  url: 6
updates:
  - at: "2026-07-14T14:19:00Z"
    level: L2
    summary: 'merged source coverage: CVE-2026-15693: Tenda BE12 Pro Stack-Based Buffer Overflow Vulnerability'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-15693
  - at: "2026-07-14T15:19:48Z"
    level: L2
    summary: added CVE-2026-15693 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-15695
  - at: "2026-07-14T15:21:01Z"
    level: L2
    summary: 'merged source coverage: Tenda BE12 Pro Buffer Overflow Vulnerability CVE-2026-15696 Publicly Disclosed'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-15696
  - at: "2026-07-14T15:25:30Z"
    level: L2
    summary: added CVE-2026-15694 +1
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-15694
---

A significant security vulnerability, CVE-2026-15691, has been identified in the Tenda BE12 Pro router, specifically impacting firmware version 16.03.66.23. The flaw is a stack-based buffer overflow located within the `fromSafeClientFilter` function, which is accessed via the `/goform/SafeClientFilter` endpoint. Attackers can remotely trigger this vulnerability by sending a crafted request that manipulates the `page` argument, leading to arbitrary code execution on the device. This vulnerability has a CVSS v3.1 Base Score of 8.8, indicating high severity. Crucially, an exploit for this vulnerability has been released to the public, increasing the immediate threat level as it can be used for active attacks by various threat actors to compromise affected routers and potentially gain access to internal networks.

## Attack Chain

1. **Initial Access**: An attacker identifies a Tenda BE12 Pro router running vulnerable firmware version 16.03.66.23, accessible from the internet.
2. **Vulnerability Discovery**: The attacker leverages publicly available information or exploit code for CVE-2026-15691, targeting the `/goform/SafeClientFilter` endpoint.
3. **Crafted HTTP Request**: The attacker constructs and sends a malicious HTTP request (GET or POST) to the `/goform/SafeClientFilter` URI on the target router.
4. **Argument Manipulation**: The crafted request includes a specially formed or excessively long value for the `page` argument, designed to exceed the allocated buffer size.
5. **Buffer Overflow Trigger**: The router's `fromSafeClientFilter` function attempts to process the manipulated `page` argument, resulting in a stack-based buffer overflow.
6. **Arbitrary Code Execution**: The overflow is exploited to overwrite the stack with attacker-controlled data, enabling the injection and execution of arbitrary code with the privileges of the affected process.
7. **Device Compromise**: Upon successful code execution, the attacker gains full control over the router, which can then be used for network reconnaissance, data exfiltration, or as a pivot point for further attacks on the internal network.

## Impact

A successful exploitation of CVE-2026-15691 allows for remote code execution on the affected Tenda BE12 Pro router. This means an attacker can gain full control over the device. The impact includes potential unauthorized access to the router's configuration, modification of network settings (such as DNS servers or firewall rules), redirection of network traffic, or the establishment of a persistent backdoor. Compromised routers can serve as a beachhead for attackers to infiltrate the internal network, intercept sensitive data, or launch further attacks against connected devices and services, posing a significant risk to the confidentiality, integrity, and availability of network resources.

## Recommendation

* **Patch CVE-2026-15691 immediately**: Update Tenda BE12 Pro routers to a patched firmware version as soon as one becomes available from the vendor.
* **Implement network segmentation**: Isolate network infrastructure devices, including routers, into dedicated network segments to limit potential lateral movement if compromised.
* **Restrict administrative access**: Ensure that Tenda BE12 Pro routers are not directly exposed to the internet via their administrative interfaces; place them behind a firewall and restrict management access to trusted IP ranges.
