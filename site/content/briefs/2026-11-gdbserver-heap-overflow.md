---
brief_id: brief-2026-11-05-gdbserver-heap-overflow
event_id: brief-2026-11-05-gdbserver-heap-overflow
revision: 1
activity_at: "2026-11-05T18:25:27Z"
title: 'GNU GDB: Heap buffer overflow in gdbserver QTDPsrc packet handler (CVE-2026-121997)'
slug: 2026-11-gdbserver-heap-overflow
description: A heap buffer overflow in the gdbserver QTDPsrc packet handler allows an unauthenticated remote attacker to achieve native code execution via crafted packet lengths.
date: "2026-11-05T18:25:27Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:gnu:gdb:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - remote-access
vendors:
  - GNU
products:
  - gdbserver
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A heap buffer overflow in gdbserver's QTDPsrc packet handler allows an unauthenticated remote attacker to achieve native code execution in the gdbserver process.
    confidence_band: high
cves:
  - id: CVE-2026-121997
    cvss: 8.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-121997
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify and restrict access to exposed gdbserver network ports
      owner: SOC
      due: 24h
      evidence: Vulnerability allows unauthenticated remote exploitation
  hunt_leads:
    - lead: Hunt for anomalous remote connections to ports used by gdbserver
      technique_id: T1203
      data_needed:
        - Network connection logs (Netflow/PCAP/Firewall)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability is exploitable via remote packets sent to the gdbserver process
  mitigation_plan:
    - priority: immediate
      action: Apply vendor patches to GDB once available
      owner: IT Operations
      addresses: CVE-2026-121997
      evidence: NVD advisory identifying the flaw in gdbserver
---

A heap buffer overflow vulnerability exists in the gdbserver component of the GNU Debugger (GDB) within the 'QTDPsrc' packet handler. The vulnerability is triggered by a discrepancy between the declared source length in a packet and the actual data length provided. This mismatch causes the 'hex2bin' function to perform an out-of-bounds write on the heap, enabling potential remote code execution by an unauthenticated attacker.

## Impact
Successful exploitation allows for native code execution in the context of the gdbserver process. The vulnerability does not require authentication.

## Recommendation
- Inventory systems running 'gdbserver' in remote debug configurations.
- Disable remote 'gdbserver' instances that are exposed to untrusted networks or the public internet.
- Patch GDB to the version containing the fix for CVE-2026-121997 as soon as the vendor release becomes available.
