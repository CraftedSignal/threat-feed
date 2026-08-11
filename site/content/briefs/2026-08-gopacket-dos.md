---
title: 'CVE-2026-54332: Unbounded Memory Allocation in GoPacket sFlow Decoder'
slug: 2026-08-gopacket-dos
description: A vulnerability in the GoPacket sFlow ExtendedGatewayFlow decoder allows unauthenticated remote attackers to trigger a massive memory allocation, resulting in a Denial of Service.
date: "2026-08-11T10:41:42Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:gopacket:gopacket:*:*:*:*:*:go:*:*
products:
  - sFlow ExtendedGatewayFlow decoder
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A specifically crafted 104-byte UDP datagram can trigger an allocation of up to 16 GiB of memory, leading to an unauthenticated remote Denial of Service (DoS) condition.
    confidence_band: high
cves:
  - id: CVE-2026-54332
    cvss: 7.5
    epss: 0.00429
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-54332
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Update all systems using GoPacket to remediate CVE-2026-54332
      owner: IT Operations
      due: 72h
      evidence: Vendor recommendation for CVE-2026-54332
---

CVE-2026-54332 affects the sFlow ExtendedGatewayFlow decoder component within the GoPacket library. The vulnerability stems from an unbounded memory allocation issue that occurs during the processing of malformed sFlow UDP packets. Specifically, a remote attacker can send a crafted 104-byte UDP datagram that triggers the decoder to attempt a memory allocation of up to 16 GiB. Because the allocation occurs before the packet structure is fully validated, an unauthenticated attacker can exhaust system memory by sending a single, small packet to any service utilizing the vulnerable decoder. This condition results in an unauthenticated remote Denial of Service (DoS) impact. Defenders should prioritize patching any software or network appliances that include the GoPacket library and process sFlow traffic.

## Impact

Successful exploitation of this vulnerability leads to a complete Denial of Service for the affected application or service. Given that the impact is memory exhaustion (OOM), the target process will likely crash immediately. This vulnerability is particularly dangerous for network infrastructure components and security monitoring platforms that rely on GoPacket for high-speed packet ingestion and decoding, as it enables an attacker to knock out critical monitoring or routing nodes with minimal bandwidth expenditure.

## Recommendation

- Identify all internal software or third-party appliances utilizing the GoPacket library and update to the patched version immediately.
- Review network configurations to restrict sFlow traffic to trusted sources, preventing untrusted external actors from reaching the vulnerable decoder.
- Monitor for abnormal process crashes or memory utilization spikes on systems responsible for processing UDP-based telemetry.
