---
title: Coder Tailnet Vulnerability (CVE-2026-55428) Leads to Route Hijacking
slug: 2026-07-coder-route-hijacking
description: A high-severity vulnerability (CVE-2026-55428) in Coder's tailnet coordinator allows a malicious workspace agent to hijack network routes by advertising arbitrary `AllowedIPs` prefixes, enabling interception and spoofing of web terminal and workspace application traffic.
date: "2026-07-06T21:04:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - cve
  - route-hijacking
  - network-attack
  - supply-chain
vendors:
  - Coder
products:
  - Coder >= 2.34.0, < 2.34.2
  - Coder >= 2.33.0, < 2.33.8
  - Coder >= 2.30.0, < 2.32.7
  - Coder < 2.29.17
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1557
    technique_name: Adversary-in-the-Middle
    evidence: A malicious workspace agent can advertise arbitrary `AllowedIPs` prefixes including another agent's tailnet address. Coder's `ServerTailnet` routes to agents by tailnet IP so an agent that claims a victim's prefix can intercept web terminal and workspace app traffic and serve spoofed content.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-wrq8-fcv5-8hvp
---

A critical vulnerability, CVE-2026-55428, has been identified in Coder's tailnet coordinator, impacting all supported versions of Coder, including 2.34, 2.33, 2.32, and 2.29 (ESR) prior to their patched releases. The flaw stems from insufficient validation of agent-supplied `AllowedIPs`, allowing a malicious Coder agent to advertise arbitrary network prefixes. This enables the agent to hijack network traffic intended for other agents, intercepting web terminal and workspace application communications, and potentially serving spoofed content. Exploitation requires an authenticated user with a running workspace and a modified agent binary. This vulnerability could lead to significant data exposure, credential theft, or further compromise of an organization's development environment. The issue was independently disclosed by Anthropic's Security Team.

## Attack Chain

1.  An authenticated user gains access to a Coder environment and initiates a workspace.
2.  The authenticated user modifies their Coder agent binary to include malicious functionality capable of manipulating `AllowedIPs` advertisements.
3.  The malicious Coder agent connects to the Coder tailnet coordinator.
4.  The malicious agent advertises arbitrary `AllowedIPs` prefixes, including the tailnet address of a target victim agent, to the coordinator.
5.  Due to the vulnerability (CVE-2026-55428), the Coder coordinator, lacking proper validation, forwards these unverified `AllowedIPs` verbatim to other tunnel peers within the tailnet.
6.  The other tunnel peers, receiving the malicious `AllowedIPs` configuration, install them into their WireGuard peer configurations, effectively re-routing traffic intended for the victim agent to the malicious agent.
7.  The malicious agent then intercepts web terminal and workspace application traffic from the victim and can serve spoofed content, facilitating data exfiltration, credential harvesting, or further exploitation.

## Impact

Successful exploitation of CVE-2026-55428 allows an attacker to perform a sophisticated Man-in-the-Middle attack within the Coder tailnet. This enables the interception of sensitive web terminal and workspace application traffic from other users or agents, potentially leading to the theft of credentials, session tokens, or proprietary data. Furthermore, the ability to serve spoofed content means attackers could phish users, deliver malicious updates, or otherwise compromise the integrity of the development environment. The vulnerability affects critical internal communication pathways, posing a severe risk to intellectual property and operational security for organizations utilizing vulnerable Coder versions.

## Recommendation

*   Immediately upgrade all affected Coder installations to the patched versions: Coder v2.34.2, v2.33.8, v2.32.7, or v2.29.17 to remediate CVE-2026-55428.
*   Monitor Coder coordinator logs for any agents advertising unexpected `AllowedIPs` prefixes, as this could indicate an attempted or successful exploitation.
*   Review network configurations to ensure that only trusted and authenticated agents are permitted to interact with the Coder tailnet coordinator.
