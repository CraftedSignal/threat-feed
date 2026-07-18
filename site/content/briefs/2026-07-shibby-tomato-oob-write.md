---
title: Shibby Tomato Router Firmware Out-of-Bounds Write Vulnerability (CVE-2026-16095)
slug: 2026-07-shibby-tomato-oob-write
description: A remote out-of-bounds write vulnerability, CVE-2026-16095, affects Shibby Tomato firmware version 1.28 RT-N5x MIPSR2 Build 124, where manipulating the `ct_tcp_timeout` argument in the `setup_conntrack` function of `/sbin/rc` can lead to memory corruption, potentially allowing arbitrary code execution or denial of service.
date: "2026-07-18T11:17:55Z"
lastmod: "2026-07-18T12:18:06Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - router
  - firmware
  - out-of-bounds-write
  - CVE-2026-16095
vendors:
  - Shibby
products:
  - Tomato 1.28 RT-N5x MIPSR2 Build 124
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Executing a manipulation of the argument ct_tcp_timeout can lead to out-of-bounds write.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Deny Access to Resource
    evidence: Executing a manipulation of the argument ct_tcp_timeout can lead to out-of-bounds write.
    confidence_band: high
cves:
  - id: CVE-2026-16095
    cvss: 8.8
  - id: CVE-2026-16096
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16095
  - https://gitee.com/Fengyi-Wang/CVE/issues/IJTQ5S
  - https://vuldb.com/cve/CVE-2026-16095
  - https://vuldb.com/submit/855123
  - https://vuldb.com/vuln/379799
  - https://vuldb.com/vuln/379799/cti
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16096
updates:
  - at: "2026-07-18T12:18:06Z"
    level: L2
    summary: added CVE-2026-16096
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-16096
---

A critical out-of-bounds write vulnerability, identified as CVE-2026-16095, has been discovered in Shibby Tomato firmware version 1.28 RT-N5x MIPSR2 Build 124. This flaw resides within the `setup_conntrack` function of the `/sbin/rc` executable, which is responsible for connection tracking. Attackers can remotely exploit this vulnerability by manipulating the `ct_tcp_timeout` argument, leading to an out-of-bounds write. This memory corruption can result in system instability, denial of service, or potentially arbitrary code execution, granting an attacker full control over the affected router. The vulnerability is assigned a CVSS v3.1 base score of 8.8 (High) and affects a superseded project, as Shibby Tomato has been replaced by FreshTomato. Organizations still utilizing this legacy firmware version face significant risk.

## Attack Chain

1. An attacker identifies a Shibby Tomato router running the vulnerable 1.28 RT-N5x MIPSR2 Build 124 firmware that is exposed and accessible on the network.
2. The attacker establishes a network connection to the vulnerable router, potentially requiring low-privileged access based on the CVSS score.
3. The attacker crafts a malicious network packet or request specifically designed to interact with the `setup_conntrack` function within the `/sbin/rc` file.
4. The malicious request includes a specially crafted value for the `ct_tcp_timeout` argument, designed to exceed expected buffer boundaries.
5. Upon processing this manipulated argument, the `setup_conntrack` function attempts to write data beyond its allocated memory buffer.
6. This out-of-bounds write operation corrupts adjacent memory, potentially overwriting critical data or code pointers within the router's operating system.
7. Depending on the specific memory corruption, this can lead to the router crashing (denial of service) or allow the attacker to execute arbitrary code with the privileges of the affected process, achieving full system compromise.

## Impact

Successful exploitation of CVE-2026-16095 can lead to severe consequences for affected organizations. The primary observed impacts include denial of service, where the vulnerable router becomes unresponsive or reboots unexpectedly due to memory corruption. More critically, an attacker could achieve arbitrary code execution, enabling them to gain full control over the router. This level of compromise allows for network reconnaissance, manipulation of network traffic, establishment of persistent backdoors, or use of the router as a pivot point for further attacks into internal networks. The high CVSS score reflects the significant confidentiality, integrity, and availability impacts on the affected device.

## Recommendation

* Immediately patch CVE-2026-16095 by updating Shibby Tomato firmware 1.28 RT-N5x MIPSR2 Build 124 to a version where this vulnerability is resolved, or migrate to FreshTomato if a direct patch is unavailable.
* Implement network segmentation to restrict remote access to router administration interfaces.
* Monitor network connection logs from router devices for unusual or malformed requests targeting device administration ports.
* Deploy a firewall to filter or inspect network traffic for anomalies that might indicate attempts to manipulate connection tracking arguments.
