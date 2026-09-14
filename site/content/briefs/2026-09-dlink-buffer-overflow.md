---
title: Remote Stack-based Buffer Overflow in D-Link DIR-878
slug: 2026-09-dlink-buffer-overflow
description: A critical stack-based buffer overflow vulnerability in the D-Link DIR-878 router enables remote code execution via malformed Dynamic DNS IPv6 configuration parameters.
date: "2026-09-14T07:31:01Z"
lastmod: "2026-09-14T09:31:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:d_link:dir_878:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - network-security
  - buffer-overflow
  - network-device
  - vulnerability
vendors:
  - D-Link
products:
  - DIR-878 (120B05)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The attack may be launched remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: The manipulation of the argument IPv6Address/Hostname results in stack-based buffer overflow.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-90692
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90692
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90693
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict access to the router web management interface to trusted internal IP ranges only.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability is remotely exploitable.
  mitigation_plan:
    - priority: immediate
      action: Check D-Link support site for firmware patches addressing CVE-2026-90692 and apply to all identified DIR-878 units.
      owner: IT Operations
      addresses: CVE-2026-90692
      evidence: Vulnerability documented in NVD.
updates:
  - at: "2026-09-14T09:31:55Z"
    level: L2
    summary: added coverage for DIR-878 (120B05)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-90693
---

D-Link DIR-878 routers running firmware version 120B05 contain a critical stack-based buffer overflow vulnerability in the SetDynamicDNSIPv6Settings function. This vulnerability resides within the device's Dynamic DNS IPv6 settings component. An unauthenticated remote attacker can exploit this flaw by sending a specially crafted request containing malicious input in the IPv6Address or Hostname arguments to the vulnerable function. Successful exploitation allows for arbitrary code execution with the privileges of the web service process. Given the nature of the overflow, it likely facilitates remote exploitation without requiring local access or previous authentication. This poses a significant risk to the availability and integrity of affected network edge devices.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve remote code execution on the router. This can lead to total device compromise, allowing the attacker to intercept network traffic, modify DNS settings for man-in-the-middle attacks, or utilize the compromised device as a pivot point for further lateral movement within the local area network.

## Recommendation

* Monitor for unauthorized attempts to access or modify dynamic DNS configurations on network edge devices.
* Audit network access control lists to ensure web management interfaces of routers like the D-Link DIR-878 are not exposed to the public internet.
* Contact D-Link support or check official vendor channels immediately for firmware updates that address the identified CVE-2026-90692 vulnerability.
