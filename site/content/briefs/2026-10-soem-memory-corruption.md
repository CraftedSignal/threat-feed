---
brief_id: brief-2026-10-26-soem-memory-corruption
event_id: brief-2026-10-26-soem-memory-corruption
revision: 1
activity_at: "2026-10-26T09:41:11Z"
title: 'SOEM: Out-of-bounds memory access (CVE-2026-70388)'
slug: 2026-10-soem-memory-corruption
description: SOEM version 2.0.0 and earlier contains an out-of-bounds memory access vulnerability due to improper arithmetic validation, allowing a network-adjacent attacker to trigger memory corruption and potential arbitrary code execution.
date: "2026-10-26T09:41:11Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:soem:soem:*:*:*:*:*:*:*:*
vendors:
  - SOEM
products:
  - SOEM (<= 2.0.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This can corrupt memory and potentially allow an attacker to execute arbitrary code on the master system.
    confidence_band: high
cves:
  - id: CVE-2026-70388
    cvss: 8.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70388
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all systems running SOEM <= 2.0.0
      owner: IT Operations
      due: 48h
      evidence: Source confirms SOEM version 2.0.0 and earlier as affected
  hunt_leads:
    - lead: Identify unauthorized or unknown network devices communicating with SOEM master nodes
      technique_id: T1203
      data_needed:
        - Network traffic logs (NetFlow, PCAP)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: A malicious device on the network can send specially crafted messages
  mitigation_plan:
    - priority: immediate
      action: Isolate SOEM master nodes from untrusted network segments
      owner: IT Operations
      addresses: CVE-2026-70388
      evidence: Source states that a malicious device on the network can exploit the vulnerability
---

SOEM version 2.0.0 and earlier contains an out-of-bounds memory access vulnerability (CVE-2026-70388). The vulnerability exists because the software performs arithmetic on message length values without proper validation, allowing negative or extremely large values to bypass safety checks. This allows a malicious device on the network to send specially crafted messages that cause the master to write data outside allocated memory boundaries. 

## Impact

Successful exploitation can lead to memory corruption, which may result in a crash of the master service or potentially allow an attacker to execute arbitrary code on the master system.

## Recommendation

Update SOEM to a patched version beyond 2.0.0 once available. In the absence of a patch, restrict network access to the master system to trusted devices only to prevent malicious actors from sending crafted network messages.
