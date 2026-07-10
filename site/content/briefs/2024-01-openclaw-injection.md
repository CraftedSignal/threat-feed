---
title: OpenClaw Lower-Trust Output Injection Vulnerability
slug: 2024-01-openclaw-injection
description: A vulnerability in OpenClaw versions 2026.4.2 and earlier allows lower-trust runtime output to be injected into trusted system events, potentially leading to prompt injection.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - openclaw
  - prompt-injection
  - vulnerability
vendors:
  - OpenClaw
products:
  - OpenClaw
references:
  - https://github.com/advisories/GHSA-gfmx-pph7-g46x
rules:
  - title: Detect OpenClaw System Event Injection
    description: Detects suspicious content within OpenClaw system events that may indicate prompt injection.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - application
      - openclaw
  - title: Detect Downgrade Async Exec Completion Mismatch
    description: Detects a mismatch in async exec completion events, potentially indicating exploitation of the downgrade vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.001
    data_sources:
      - application
      - openclaw
rules_count: 2
---

OpenClaw, a user-controlled local assistant, is vulnerable to a trust model issue where lower-trust runtime or background output can be improperly promoted into trusted System events. This vulnerability, affecting OpenClaw versions up to and including 2026.4.2, can result in the injection of malicious prompts into subsequent agent turns. The issue was identified and reported by @tdjackey. Successful exploitation of this vulnerability could allow an attacker to influence the behavior of the OpenClaw assistant by injecting arbitrary commands or instructions into the system's trusted event stream. The patched version, 2026.4.8, resolves this vulnerability.

## Attack Chain

1. A user interacts with the OpenClaw assistant, triggering a background runtime process.
2. The background runtime process generates output that is intended to be treated as lower-trust.
3. Due to the vulnerability, this lower-trust output is improperly categorized.
4. The improperly categorized output is injected into the trusted "System:" event stream.
5. The injected content is processed as a legitimate system event in a later turn.
6. This allows an attacker to inject malicious prompts into the assistant's workflow.
7. The assistant executes the injected prompts, potentially leading to unintended actions or information disclosure.

## Impact

The primary impact of this vulnerability is the potential for prompt injection. By injecting malicious prompts into the trusted system event stream, an attacker could influence the behavior of the OpenClaw assistant. This could lead to information disclosure, unauthorized actions, or other security breaches. This vulnerability affects deployments using OpenClaw versions 2026.4.2 and earlier.

## Recommendation

- Upgrade OpenClaw to version 2026.4.8 or later to remediate the vulnerability.
- Monitor OpenClaw logs for unexpected or suspicious system events.
- Review and adjust the trust model configuration of OpenClaw to minimize the risk of similar vulnerabilities in the future.
