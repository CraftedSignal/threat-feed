---
title: OpenClaw Gateway Configuration Mutation Vulnerability
slug: 2026-05-openclaw-config-mutation
description: A vulnerability in OpenClaw versions before 2026.4.23 allows a compromised model with access to the `gateway` tool to persist unsafe config changes that cross security boundaries due to an insufficient denylist.
date: "2026-05-05T18:44:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - config-mutation
  - vulnerability
vendors:
  - OpenClaw
products:
  - openclaw
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
references:
  - https://github.com/advisories/GHSA-cwj3-vqpp-pmxr
rules:
  - title: Detect OpenClaw Gateway Config Apply/Patch with Suspicious Arguments
    description: Detects attempts to use 'gateway config.apply' or 'gateway config.patch' commands with unusual arguments, potentially indicating an exploitation attempt.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    data_sources:
      - process_creation
      - linux
  - title: Detect Modification of OpenClaw Configuration Files
    description: Detects modification of OpenClaw configuration files, which could indicate a malicious configuration change.
    platform: sigma
    severity: high
    tactics:
      - persistence
    data_sources:
      - file_event
      - linux
rules_count: 2
---

OpenClaw versions prior to 2026.4.23 contain a vulnerability where a compromised model, granted access to the owner-only `gateway` tool, can exploit an insufficient denylist used to protect configuration settings. This denylist, intended as a model-to-operator trust boundary, failed to keep pace with the evolving config schema. This allowed sensitive subtrees to be writable through model-driven gateway config mutations. The vulnerability was addressed in version 2026.4.23 by replacing the denylist with a more secure fail-closed allowlist, restricting agent-driven configuration changes. The vulnerable entry point is owner-only, emphasizing the importance of securing the model/agent interface, which should not be considered a trusted principal.

## Attack Chain

1. An attacker gains unauthorized access to a model with access to the `gateway` tool, potentially through prompt injection or other compromise techniques.
2. The attacker crafts a malicious configuration payload designed to exploit the incomplete denylist.
3. The attacker uses the `gateway config.apply` or `gateway config.patch` command to submit the crafted configuration.
4. The compromised model interacts with the `gateway` tool to apply the malicious configuration changes, bypassing the insufficient denylist.
5. The malicious configuration changes are written to the OpenClaw configuration files.
6. The configuration changes persist even after OpenClaw restarts.
7. These persisted changes allow the attacker to manipulate command execution, network behavior, credential forwarding, telemetry or hook endpoints, memory/indexing surfaces, and operator policy controls.
8. The attacker achieves persistent control over OpenClaw's behavior, potentially leading to data exfiltration, service disruption, or privilege escalation.

## Impact

Successful exploitation of this vulnerability allows attackers to persist unsafe configuration changes within OpenClaw. These changes can affect critical system functions, including command execution, network/proxy/TLS behavior, credential forwarding, telemetry or hook endpoints, memory/indexing surfaces, and operator policy controls. The changes survive restarts, granting the attacker persistent control. While the specific number of affected installations is unknown, any OpenClaw instance running a version prior to 2026.4.23 is vulnerable.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.23 or later to incorporate the fix that replaces the denylist with a fail-closed allowlist.
*   Implement strict input validation and sanitization for any data passed to the `gateway` tool to prevent prompt injection attacks, addressing the vulnerability described in the overview.
*   Monitor the execution of `gateway config.apply` and `gateway config.patch` commands for unexpected arguments or payloads that may indicate exploitation attempts, creating a detection opportunity based on observed command execution.
*   Enable file integrity monitoring on OpenClaw configuration files to detect unauthorized modifications, providing an alert mechanism if malicious changes persist on disk.
