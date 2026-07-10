---
title: OpenClaw ACP Bypass via Conflicting Tool Identity Hints
slug: 2024-01-openclaw-acp-bypass
description: OpenClaw versions prior to 2026.3.22 are vulnerable to a bypass of dangerous-tool prompting due to conflicting tool identity hints in ACP permission resolution.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openclaw
  - acp
  - bypass
  - npm
vendors:
  - OpenClaw
products:
  - openclaw
references:
  - https://github.com/advisories/GHSA-74wf-h43j-vvmj
rules:
  - title: Detect OpenClaw ACP Bypass Attempt via Conflicting Tool Identity
    description: Detects potential attempts to bypass OpenClaw's ACP by identifying instances where tool identity hints from raw input and metadata conflict. This rule requires access to OpenClaw's internal logging or instrumentation that exposes the tool identity resolution process.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - app_log
      - openclaw
  - title: Detect OpenClaw Dangerous-Tool Prompt Suppression
    description: Detects attempts to suppress dangerous-tool prompts in OpenClaw, which could indicate exploitation of the ACP bypass vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - app_log
      - openclaw
rules_count: 2
---

The `openclaw` npm package, in versions before 2026.3.22, contains a flaw in its ACP (Access Control Policy) permission resolution logic. This vulnerability arises from the ACP client incorrectly trusting conflicting tool identity hints derived from both raw input and metadata. An attacker could exploit this by manipulating the tool identity hints, specifically through spoofable raw input, to suppress dangerous-tool prompting. This could lead to the execution of potentially harmful operations without proper user confirmation. The vulnerability was reported by @zpbrent and patched in version 2026.3.22. The fix ensures that the ACP client fails closed when there are conflicting tool identity hints.

## Attack Chain

1. An attacker crafts a malicious OpenClaw tool with conflicting identity hints in its raw input and metadata.
2. The user attempts to execute the malicious OpenClaw tool.
3. The ACP client within OpenClaw receives the execution request.
4. The ACP client attempts to resolve permissions based on tool identity hints.
5. Due to the vulnerability, the ACP client trusts the spoofed raw input, which conflicts with the metadata.
6. The dangerous-tool prompt is suppressed because of the conflicting identities.
7. The malicious tool executes with elevated permissions.
8. The attacker achieves their objective, potentially compromising the system or data.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass security prompts intended to warn users about potentially dangerous tools. This can lead to the execution of malicious code with elevated privileges, potentially resulting in data theft, system compromise, or other malicious activities. While the exact number of affected users is unknown, any application relying on the `openclaw` package for access control is potentially vulnerable.

## Recommendation

- Upgrade the `openclaw` npm package to version 2026.3.22 or later to remediate the vulnerability (reference affected versions).
- Deploy the Sigma rule provided to detect potential attempts to exploit this vulnerability by monitoring for conflicting tool identity hints (reference Sigma rule).
- Audit existing OpenClaw integrations to identify potential attack vectors involving manipulation of raw input to influence ACP decisions.
