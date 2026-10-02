---
title: Memory Exhaustion Vulnerability in Mooncake Transfer Engine
slug: 2026-10-mooncake-dos
description: An unauthenticated memory exhaustion vulnerability in the Mooncake transfer engine (CVE-2026-103761) allows remote attackers to trigger a denial-of-service condition by repeatedly sending large notify frames to the handshake RPC port.
date: "2026-10-02T00:19:56Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:mooncake:transfer_engine:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - network
vendors:
  - Mooncake
products:
  - Mooncake transfer engine (<= 0.3.13.post1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can repeatedly send notify frames up to 1 MB to the handshake RPC port, filling the uncapped notifys vector until the out-of-memory killer terminates the engine.
    confidence_band: high
cves:
  - id: CVE-2026-103761
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103761
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Implement rate limiting on the handshake RPC port used by Mooncake.
      owner: IT Operations
      due: 24h
      evidence: Source describes vulnerability as addressable by limiting frame transmission.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to a version later than 0.3.13.post1 when available.
      owner: IT Operations
      addresses: CVE-2026-103761
      evidence: NVD states versions through 0.3.13.post1 are vulnerable.
---

The Mooncake transfer engine, in versions up to and including 0.3.13.post1, is susceptible to a memory exhaustion vulnerability located within the TransferMetadata::receivePeerNotify function. This vulnerability stems from a lack of bounds checking on the notifys vector, which handles incoming peer notification frames. An unauthenticated attacker can exploit this by repeatedly transmitting 1 MB notify frames to the handshake RPC port. Because the system does not cap the size or count of these frames, the process memory usage grows monotonically until the operating system's out-of-memory (OOM) killer is invoked to terminate the engine. This results in a persistent denial-of-service condition, impacting the availability of the transfer service. Defenders should prioritize updating to the next patched release once available and implement rate limiting on the RPC handshake port to mitigate exploitation attempts.

## Impact

Successful exploitation results in the immediate termination of the Mooncake transfer engine process via the system OOM killer, causing a denial-of-service. This impacts any infrastructure relying on Mooncake for data transfer operations. No data modification or execution is currently associated with this memory exhaustion vulnerability, but the interruption of service could disrupt critical business processes.

## Recommendation

- Monitor RPC traffic to the handshake port for high volumes of large frames (1 MB) originating from unauthorized sources.
- Apply network-level rate limiting or connection throttling on the handshake RPC port as an immediate defensive measure.
- Monitor system logs for OOM killer events or unexpected crashes of the Mooncake process.
- Upgrade the Mooncake transfer engine to a version beyond 0.3.13.post1 immediately upon vendor release.
