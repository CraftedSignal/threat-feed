---
title: Heap Buffer Overflow in ntop nDPI
slug: 2026-09-ndpi-buffer-overflow
description: Versions of ntop nDPI before 6.0 are vulnerable to a heap-based buffer overflow in the ndpi_json_string_escape function, allowing attackers to trigger memory corruption via crafted network traffic.
date: "2026-09-04T23:28:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ntop:ndpi:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - network-security
vendors:
  - ntop
products:
  - nDPI (< 6.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can trigger the overflow by supplying crafted network packet data including TLS SNI, HTTP headers, or DNS names that reach the vulnerable function, causing heap corruption.
    confidence_band: high
cves:
  - id: CVE-2026-86098
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86098
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade ntop nDPI to version 6.0 or later
      owner: IT Operations
      addresses: CVE-2026-86098
      evidence: Source states versions before 6.0 are vulnerable.
---

ntop nDPI versions prior to 6.0 contain a critical heap-based buffer overflow vulnerability located in the ndpi_json_string_escape function. This function is responsible for escaping strings during JSON serialization of captured network metadata. The vulnerability occurs when the function processes overly long or specially formatted input strings, leading to an out-of-bounds write beyond caller-supplied buffer boundaries. An attacker can trigger this vulnerability by providing malicious network traffic containing crafted TLS SNI fields, HTTP headers, or DNS names that are subsequently parsed and processed by nDPI. Successful exploitation of this vulnerability leads to heap memory corruption, which may result in application crashes or, potentially, arbitrary code execution within the context of the process running the nDPI library. Given that nDPI is widely used in network traffic analysis and security monitoring tools, this vulnerability presents a significant risk to the integrity and stability of security infrastructure.

## Impact

Successful exploitation of CVE-2026-86098 could result in denial-of-service conditions due to application crashes or unauthorized code execution. Because nDPI is integrated into many network monitoring, IDS, and traffic analysis solutions, victims include organizations utilizing these tools for deep packet inspection. The corruption of heap memory can lead to unstable system states, potentially allowing an attacker to bypass security controls or gain persistent access to the network analysis environment.

## Recommendation

- Upgrade ntop nDPI to version 6.0 or later immediately to address the vulnerability documented in CVE-2026-86098.
- Audit network monitoring devices or security applications that incorporate the nDPI library for potential exposure.
- Restrict access to network analysis interfaces and ensure that traffic processing nodes are segmented from critical internal systems.
