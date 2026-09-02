---
title: Integer Overflow Vulnerability in EVerest SDP Parsing
slug: 2026-09-everest-dos
description: An integer overflow vulnerability (CVE-2025-68137) in EVerest everest-core versions prior to 2025.10.0 allows unauthenticated attackers to cause a Denial of Service or potential code execution.
date: "2026-09-02T15:43:34Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:everest:everest-core:*:*:*:*:*:*:*:*
  - cpe:2.3:o:linuxfoundation:everest:*:*:*:*:*:*:*:*
tags:
  - dos
  - vulnerability
  - cve-2025-68137
vendors:
  - EVerest
products:
  - everest-core (< 2025.10.0)
affected_os:
  - Ubuntu 22.04
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An integer overflow in SdpPacket::parse_header() allows an attacker to trigger either an infinite loop (TCP) or stack buffer overflow (TLS) by sending a malformed SDP packet.
    confidence_band: high
cves:
  - id: CVE-2025-68137
    cvss: 8.3
    epss: 0.00263
references:
  - https://www.exploit-db.com/exploits/52679
  - https://nvd.nist.gov/vuln/detail/CVE-2025-68137
  - https://github.com/EVerest/EVerest/security/advisories/GHSA-7qq4-q9r8-wc7w
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade EVerest everest-core to 2025.10.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source explicitly identifies version 2025.10.0 as the fix.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to EVerest services to known management networks
      owner: IT Operations
      addresses: CVE-2025-68137
---

EVerest everest-core versions prior to 2025.10.0 contain an integer overflow vulnerability in the SdpPacket::parse_header() function. The vulnerability occurs because the header length field (4 bytes) is added to the fixed header size (8 bytes) without performing an overflow check. When a length field is provided that causes this addition to exceed the capacity of an unsigned integer (near UINT_MAX), it triggers an incorrect size calculation.

This flaw can be exploited by an unauthenticated attacker sending a malformed SDP packet over the network. If the service is running over TCP, the overflow causes an infinite loop in the packet parsing logic, leading to a Denial of Service. If the service is running over TLS, the resulting incorrect size calculation can trigger a stack-based buffer overflow, which may allow for remote code execution. This vulnerability is documented as CVE-2025-68137 and a functional proof-of-concept exploit exists for the DoS condition.

## Impact

Successful exploitation of this vulnerability results in service disruption, as the affected instance of EVerest will hang indefinitely upon processing a malicious SDP packet. In TLS-enabled deployments, the stack-based buffer overflow presents a significant risk of remote code execution, allowing an attacker to gain control over the affected system. This vulnerability affects systems using EVerest core versions prior to 2025.10.0, impacting environments where the software is deployed for EV charging infrastructure management.

## Recommendation

1. Upgrade all instances of EVerest everest-core to version 2025.10.0 or later immediately to patch CVE-2025-68137.
2. Restrict network access to EVerest management interfaces to trusted IP addresses to prevent unauthenticated access to the SDP service.
3. Deploy network-level inspection to identify and block SDP packets with highly anomalous length fields (near 0xFFFFFFFF).
