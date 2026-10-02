---
title: Arbitrary Memory Access Vulnerability in Mooncake Transfer Engine
slug: 2026-10-mooncake-memory-corruption
description: An untrusted pointer dereference vulnerability (CVE-2026-103764) in the Mooncake transfer engine allows unauthenticated attackers to perform arbitrary memory reads and writes, potentially leading to remote code execution.
date: "2026-10-02T00:19:35Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:mooncake:transfer_engine:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - memory-corruption
vendors:
  - Mooncake
products:
  - transfer engine (< 0.3.13)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can exploit this via the TCP transport data port by sending a crafted SessionHeader.
    confidence_band: high
cves:
  - id: CVE-2026-103764
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-103764
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Mooncake transfer engine to 0.3.13 or later
      owner: IT Operations
      due: 24h
      evidence: Source states versions before 0.3.13 are vulnerable.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the Mooncake TCP transport data port
      owner: Security Operations
      addresses: CVE-2026-103764
      evidence: Attack requires reachability to the TCP transport data port.
---

The Mooncake transfer engine prior to version 0.3.13 is susceptible to an untrusted pointer dereference vulnerability residing in the ServerSession::readHeader function. This flaw allows unauthenticated remote attackers to interact with the service over its TCP transport data port. By crafting a malicious SessionHeader containing arbitrary address and size fields, an attacker can issue READ or WRITE opcodes. These operations enable the unauthorized disclosure of sensitive internal information, such as KV cache contents, prompts, and system secrets. Furthermore, the ability to perform arbitrary memory writes allows for potential memory corruption, which may be leveraged to achieve remote code execution on the host running the transfer engine. Given the severity of this vulnerability and the lack of authentication requirements, defenders should prioritize patching to version 0.3.13 or later.

## Impact

Successful exploitation of CVE-2026-103764 results in full compromise of the affected process memory. Impact includes the theft of sensitive proprietary data, such as cached prompts and secrets, and potential full system compromise via arbitrary code execution. This impacts any environment deploying Mooncake transfer engine versions prior to 0.3.13 exposed to untrusted network segments.

## Recommendation

- Upgrade the Mooncake transfer engine to version 0.3.13 or later immediately to address the underlying pointer dereference flaw.
- Restrict network access to the Mooncake TCP transport data port to trusted IP addresses only, reducing the attack surface until patches can be applied.
- Monitor network traffic for anomalous sequences targeting the transfer engine port, specifically looking for header anomalies or large-scale data transfer patterns indicative of memory dumping.
