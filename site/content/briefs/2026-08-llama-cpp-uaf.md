---
title: Use-After-Free Vulnerability in llama.cpp RPC Server
slug: 2026-08-llama-cpp-uaf
description: An unauthenticated use-after-free vulnerability in the llama.cpp RPC server's GRAPH_RECOMPUTE handler allows remote attackers to achieve arbitrary read/write access and remote code execution.
date: "2026-08-21T17:25:19Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - ggerganov
products:
  - llama.cpp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attackers can send RPC requests to trigger re-execution of stored graphs with dangling pointers, enabling full remote code execution.
    confidence_band: med
cves:
  - id: CVE-2026-39909
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39909
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade llama.cpp to version b8585 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-39909 patch requirement
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to RPC server ports
      owner: IT Operations
      addresses: CVE-2026-39909
      evidence: Network-based exploitation vector
---

The llama.cpp RPC server, used for distributed model inference, contains a critical use-after-free vulnerability (CVE-2026-39909) affecting all versions prior to b8585. An unauthenticated remote attacker can exploit this vulnerability by interacting with the RPC interface specifically via the GRAPH_RECOMPUTE handler. The flaw arises from improper memory management during the handling of computation graphs. By storing a specific graph structure, forcing the server to free associated buffers, and subsequently reclaiming that freed memory with attacker-supplied content, an attacker can leave the server with dangling pointers. Subsequent requests to re-execute the graph trigger these pointers, leading to arbitrary memory read and write operations. This capability provides a pathway for remote code execution, posing a significant risk to systems exposing the llama.cpp RPC server to untrusted networks.

## Impact

Successful exploitation allows an unauthenticated remote attacker to gain arbitrary read and write access to the memory space of the llama.cpp process. This effectively results in remote code execution on the underlying host. The impact is significant for organizations deploying large language model inference clusters where the RPC server is reachable from broader network segments, as it provides a direct entry point for system compromise without requiring user interaction or authentication.

## Recommendation

1. Upgrade all instances of llama.cpp to version b8585 or later immediately to patch CVE-2026-39909.
2. Restrict network access to the llama.cpp RPC server interface via firewall or network segmentation to ensure it is not reachable from untrusted or public networks.
3. Implement egress filtering for servers running llama.cpp to limit the potential for post-exploitation data exfiltration or secondary payload delivery if an initial compromise occurs.
