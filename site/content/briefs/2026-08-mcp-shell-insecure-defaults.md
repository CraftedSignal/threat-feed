---
title: mcp-shell Insecure Configuration and Allowlist Bypass
slug: 2026-08-mcp-shell-insecure-defaults
description: mcp-shell versions prior to 0.6.0 suffer from default-disabled security settings and insecure allowlists, enabling unauthenticated arbitrary command execution via connected LLM agents.
date: "2026-08-25T16:02:06Z"
lastmod: "2026-08-25T16:02:20Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
tags:
  - vulnerability
  - rce
  - mcp
  - llm-security
vendors:
  - sonirico
products:
  - mcp-shell
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The default security.yaml includes both /bin/bash and /usr/bin/python3 in allowed_executables.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The attacker, typically an LLM connected via stdio, can leverage these flaws to gain arbitrary code execution.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-f5pj-2738-996m
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55580
  - https://github.com/advisories/GHSA-74hp-mggr-hv58
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade mcp-shell to 0.6.0+ across all environments.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-55580 requires patching to remediate default insecure configurations.
  mitigation_plan:
    - priority: immediate
      action: Remove shell interpreters from the security.yaml allowlist.
      owner: Security Engineering
      addresses: CVE-2026-55580
      evidence: Source explicitly identifies bash and python as bypass vectors.
updates:
  - at: "2026-08-25T16:02:20Z"
    level: L2
    summary: poc_available; OS linux
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-74hp-mggr-hv58
---

mcp-shell, a tool designed to provide shell execution capabilities to Large Language Models (LLMs) via the Model Context Protocol (MCP), contains two critical configuration flaws that negate its security controls. First, the application ships with security features disabled by default in `config.go`. Unless an operator explicitly defines the `MCP_SHELL_SEC_CONFIG_FILE` environment variable, the `validateCommand` function short-circuits and allows all incoming commands without restriction. Second, the default `security.yaml` configuration included in the Docker image provides an insecure allowlist containing shell interpreters such as `/bin/bash` and `/usr/bin/python3`. 

These flaws enable an LLM connected to the mcp-shell server to execute arbitrary commands on the underlying system. The attack surface is significant because mcp-shell operates via stdio transport; an attacker (or a compromised/misaligned LLM agent) can issue `shell_exec` calls that bypass validation either due to the "disabled by default" state or by abusing allowed interpreters to execute nested command strings, effectively bypassing metacharacter filters. These vulnerabilities affect all deployments prior to version 0.6.0, including source-based and official container-based installations.

## Attack Chain

1. The operator deploys mcp-shell using default installation steps (git clone or official Docker image).
2. The operator fails to explicitly set the `MCP_SHELL_SEC_CONFIG_FILE` environment variable, leaving the security module in a disabled state (Finding 1) OR the operator uses the default `security.yaml` which permits shell interpreters (Finding 2).
3. The attacker (e.g., a malicious or poisoned LLM) establishes a session with the mcp-shell server over the stdio transport.
4. The attacker sends a `tools/call` request to the mcp-shell server specifying the `shell_exec` method.
5. The server process receives the command request; if security is disabled, it proceeds directly to system execution.
6. If in "secure mode" with an insecure allowlist, the attacker executes `/bin/bash -c '<arbitrary_command>'` which the server permits because `/bin/bash` is on the allowlist and the string contains no forbidden metacharacters.
7. The server process spawns the interpreter, which in turn executes the embedded malicious payload.
8. The attacker achieves arbitrary code execution on the host with the privileges of the mcp-shell process.

## Impact

Successful exploitation allows for full arbitrary command execution on the host system running mcp-shell. Given that mcp-shell is designed to interact with LLMs, this can result in unauthorized data exfiltration, system configuration changes, and lateral movement from the host. Because the threat model involves LLMs acting as the agent, the vulnerability is reachable without network-level access, provided the LLM has been tricked or configured to invoke the `shell_exec` tool.

## Recommendation

1. Upgrade mcp-shell to version 0.6.0 or higher immediately to address the insecure default configurations and updated example allowlists.
2. For existing deployments, manually create a restrictive `security.yaml` that excludes all shell interpreters (e.g., `bash`, `sh`, `python`, `perl`, `ruby`) and enforce `Enabled: true` in the configuration.
3. Set the `MCP_SHELL_SEC_CONFIG_FILE` environment variable explicitly in all deployment environments (including Kubernetes/Docker orchestrators) to ensure validation is active.
4. Implement strict sandboxing (e.g., Docker containers with minimal capabilities or separate namespaces) for mcp-shell processes as a layer of defense-in-depth, acknowledging that sandboxing does not mitigate the primary vulnerability of unauthorized intra-session command execution.
