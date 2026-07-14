---
title: 'CVE-2026-15692: Tenda BE12 Pro Stack-Based Buffer Overflow Vulnerability'
slug: 2026-07-tenda-be12-pro-overflow
description: A stack-based buffer overflow vulnerability, identified as CVE-2026-15692, exists in Tenda BE12 Pro firmware version 16.03.66.23's `fromSafeUrlFilter` function, allowing remote attackers to achieve arbitrary code execution by manipulating the 'page' argument via a crafted HTTP request, with a public exploit available.
date: "2026-07-14T13:30:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - buffer-overflow
  - rce
  - firmware
  - router
  - network-device
vendors:
  - Tenda
products:
  - BE12 Pro (16.03.66.23)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This vulnerability affects the function fromSafeUrlFilter of the file /goform/SafeUrlFilter. The attack may be performed from remote.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Executing a manipulation of the argument page can lead to stack-based buffer overflow.
    confidence_band: high
cves:
  - id: CVE-2026-15692
    cvss: 8.8
references:
  - https://github.com/cve-a/dexingzhiqing/issues/2
  - https://vuldb.com/cve/CVE-2026-15692
  - https://vuldb.com/submit/856010
  - https://vuldb.com/vuln/378239
  - https://vuldb.com/vuln/378239/cti
  - https://www.tenda.com.cn/
iocs:
  - type: url
    value: https://github.com/cve-a/dexingzhiqing/issues/2
  - type: url
    value: https://vuldb.com/cve/CVE-2026-15692
  - type: url
    value: https://vuldb.com/submit/856010
  - type: url
    value: https://vuldb.com/vuln/378239
  - type: url
    value: https://vuldb.com/vuln/378239/cti
  - type: url
    value: https://www.tenda.com.cn/
ioc_counts:
  url: 6
rules:
  - title: Detects CVE-2026-15692 Exploitation - Tenda BE12 Pro Overflow Attempt
    description: Detects CVE-2026-15692 exploitation attempts targeting Tenda BE12 Pro routers via a stack-based buffer overflow in the /goform/SafeUrlFilter endpoint by looking for suspicious characters or patterns in the 'page' argument.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
      - T1203
    data_sources:
      - webserver
rules_count: 1
---

A critical stack-based buffer overflow vulnerability, tracked as CVE-2026-15692, has been discovered in the Tenda BE12 Pro wireless router, specifically in firmware version 16.03.66.23. The flaw resides within the `fromSafeUrlFilter` function of the `/goform/SafeUrlFilter` file. Attackers can remotely exploit this weakness by sending a specially crafted HTTP request that manipulates the `page` argument. This manipulation leads to a buffer overflow, which can be leveraged to achieve arbitrary code execution on the device. The vulnerability carries a CVSS v3.1 base score of 8.8 (High) and is particularly concerning as an exploit has been made publicly available, increasing the likelihood of widespread exploitation. This vulnerability affects the device's core functionality, enabling potential compromise of network infrastructure.

## Attack Chain

1. An attacker, with network access to the Tenda BE12 Pro device, identifies the vulnerable `/goform/SafeUrlFilter` endpoint.
2. The attacker crafts an HTTP POST request targeting this endpoint.
3. The request includes a `page` argument within the `cs-uri-query` that is malformed or excessively long, designed to exceed the buffer allocated for it in the `fromSafeUrlFilter` function.
4. The vulnerable `fromSafeUrlFilter` function attempts to process the manipulated `page` argument, triggering a stack-based buffer overflow.
5. The overflow overwrites adjacent memory regions on the stack, allowing the attacker to inject and execute arbitrary code.
6. Upon successful exploitation, the attacker gains remote code execution capabilities on the Tenda BE12 Pro router.
7. This RCE can lead to full compromise of the device, allowing the attacker to establish persistence, exfiltrate data, or pivot to other systems on the internal network.

## Impact

Successful exploitation of CVE-2026-15692 grants remote attackers arbitrary code execution on the Tenda BE12 Pro router. This can lead to a complete compromise of the affected device, resulting in a loss of confidentiality, integrity, and availability of the network traffic passing through the router. Attackers could redirect traffic, steal sensitive information, use the router as a foothold for further attacks on the internal network, or disrupt internet access for connected users. As a critical network device, its compromise can severely impact business operations and data security. The public availability of exploit details increases the risk of targeted and widespread attacks.

## Recommendation

* Immediately update Tenda BE12 Pro devices to a patched firmware version when available to remediate CVE-2026-15692.
* Deploy the provided Sigma rule to your SIEM to detect attempts to exploit CVE-2026-15692 by monitoring webserver logs for suspicious `cs-uri-query` patterns on `/goform/SafeUrlFilter`.
* Implement network segmentation to isolate critical systems and reduce the potential impact of compromised edge devices like routers.
* Review web server access logs for requests matching the patterns described in the Sigma rule and any associated IOCs from the references.
