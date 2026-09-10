---
title: Unauthenticated Remote Task Execution in @yeger/turbo-graph
slug: 2026-09-turbo-graph-rce
description: The @yeger/turbo-graph package exposes an unauthenticated HTTP endpoint (/api/run) that binds to all network interfaces, allowing adjacent attackers to execute arbitrary Turborepo tasks defined in the victim repository.
date: "2026-09-10T00:51:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - nodejs
  - insecure-api
vendors:
  - yeger
products:
  - turbo-graph (2.8.8)
affected_os:
  - windows
  - linux
  - macos
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The server uses spawn() to execute arbitrary tasks defined in the victim repository, resulting in code execution.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any adjacent-network attacker can send an unauthenticated GET request to trigger arbitrary tasks defined in the victim's repository.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2r5q-h53f-9rp3
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Audit developer workstations for active node processes running @yeger/turbo-graph
      owner: SOC
      due: 24h
      evidence: Source documentation identifies port 29312 as the default listening port
  mitigation_plan:
    - priority: immediate
      action: Configure host-based firewall to block ingress traffic on port 29312
      owner: IT Operations
      addresses: Network-exposed API
      evidence: Insecure binding to 0.0.0.0 enables remote network exploitation
---

The `@yeger/turbo-graph` package (specifically version 2.8.8) contains a critical vulnerability due to insecure default configuration and the absence of authentication on its administrative API. The application's embedded Next.js server fails to bind to the local loopback interface (localhost), defaulting instead to `0.0.0.0` and `::`. This exposes the service to the entire network segment. 

The `/api/run` endpoint is designed to trigger Turborepo tasks; however, it lacks any authentication, authorization, CSRF protections, or task allowlisting. An adjacent attacker can send a simple GET request containing the name of any task defined in the victim's `turbo.json` file. The server then uses `spawn()` to execute these tasks with the privileges of the developer's operating system user. This allows attackers to perform malicious actions including sensitive data exfiltration, file modification, or unauthorized infrastructure deployment depending on the tasks configured within the target repository.

## Attack Chain

1. The victim starts the `turbo-graph` development utility in a repository that contains a `turbo.json` file.
2. The application's Node.js `listen()` call executes without a hostname constraint, causing the server to bind to all network interfaces (e.g., `0.0.0.0:29312`).
3. The attacker performs network reconnaissance to identify active services on port `29312` within the local network segment.
4. The attacker crafts a malicious HTTP GET request to the `/api/run` endpoint, supplying the target task name via the `tasks` query parameter.
5. The server receives the unauthenticated request and immediately passes the user-supplied task argument to the `buildResponseFromArgs` function.
6. The `buildResponseFromArgs` function constructs a `turbo` CLI argument array and calls `spawn()` to execute the specified task.
7. The operating system executes the requested task script (defined in the `package.json` scripts) under the context of the victim's user session, completing the RCE objective.

## Impact

The vulnerability poses a high risk to development environments where `turbo-graph` is utilized. Because it requires no credentials and targets a default static port, internal lateral movement or network-adjacent exploitation is highly trivial. Successful exploitation results in full remote code execution in the context of the developer, potentially leading to the theft of environment variables, SSH keys, cloud credentials, or persistent compromise of the developer's workstation and internal build infrastructure.

## Recommendation

Prioritize the immediate decommissioning of `@yeger/turbo-graph` version 2.8.8 until an official patch is applied or binding behavior is corrected.

* Identify any instances of `turbo-graph` listening on non-loopback interfaces using host-level process monitoring or network auditing.
* Restrict network access to port `29312` via host-based firewalls (e.g., `iptables`, `nftables`, or Windows Firewall) to ensure only local traffic can reach the service.
* Monitor for unusual process spawns originating from the `turbo-graph` process (or its parent process) that correlate with inbound network connections to the development port.
