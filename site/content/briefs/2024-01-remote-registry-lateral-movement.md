---
title: Remote Registry Lateral Movement via RPC Firewall
slug: 2024-01-remote-registry-lateral-movement
description: This brief details detection of lateral movement attempts using remote RPC calls to modify the registry, potentially leading to code execution, detected via RPC Firewall logs.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - lateral-movement
  - defense-impairment
  - persistence
  - rpc
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1112
    technique_name: Modify Registry
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78
  - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/ddd4608fe8684fcf2fcf9b48c5f0b3c28097f8a3/documents/MS-RRP.md
  - https://github.com/zeronetworks/rpcfirewall
  - https://zeronetworks.com/blog/stopping-lateral-movement-via-the-rpc-firewall/
rules:
  - title: RPC Firewall Remote Registry Modification
    description: Detects RPC calls indicative of remote registry modification using RPC Firewall logs.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
      - lateral-movement
      - persistence
    techniques:
      - T1112
    data_sources:
      - application
      - rpc_firewall
  - title: RPC Firewall Remote Registry Add Key
    description: Detects RPC calls indicative of remote registry key addition using RPC Firewall logs.
    platform: sigma
    severity: high
    tactics:
      - defense-impairment
      - lateral-movement
      - persistence
    techniques:
      - T1112
    data_sources:
      - application
      - rpc_firewall
rules_count: 2
---

This threat brief focuses on detecting lateral movement attempts that leverage remote procedure calls (RPC) to modify registry keys on target systems. The technique abuses the remote registry protocol to achieve persistence or execute arbitrary code. Defenders can use RPC Firewall logs to identify and block this activity, specifically by monitoring for calls to the Registry Remote Protocol (MS-RRP) interface with specific operation numbers indicative of registry manipulation. This activity is often associated with post-exploitation phases, where attackers attempt to gain a foothold and expand their control within a network. The RPC Firewall detailed in this brief allows for monitoring and blocking of this behavior.

## Attack Chain

1.  The attacker gains initial access to a system within the network (e.g., through phishing or exploiting a vulnerability).
2.  The attacker discovers accessible target systems on the network.
3.  The attacker attempts to connect to the target system's RPC endpoint for the Remote Registry service (UUID 338cd001-2244-31f1-aaaa-900038001003).
4.  The attacker uses RPC calls with operation numbers 6, 7, 8, 13, 18, 19, 21, 22, 23, or 35 to interact with the registry remotely.
5.  The attacker modifies registry keys related to startup programs or services.
6.  The attacker triggers the execution of malicious code through the modified registry keys, achieving persistence.
7.  The malicious code executes, allowing the attacker to perform actions such as data exfiltration or further lateral movement.

## Impact

Successful exploitation allows attackers to achieve persistence, escalate privileges, and move laterally within the network. This can lead to data theft, system compromise, and disruption of services. If lateral movement succeeds, attackers can gain control over critical assets, leading to significant financial and reputational damage.

## Recommendation

*   Install and configure RPC Firewall on all critical systems, auditing RPC calls to the Registry Remote Protocol interface (UUID 338cd001-2244-31f1-aaaa-900038001003) as described in the `definition` within the `logsource` section.
*   Deploy the provided Sigma rule to your SIEM to detect anomalous RPC calls related to registry modification as outlined in the `detection` section.
*   Investigate and block any identified malicious RPC connections using RPC Firewall based on the logs generated and reviewed from the deployed Sigma rule.
