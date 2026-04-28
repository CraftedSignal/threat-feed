---
title: OpenClaw Authorization Bypass Vulnerability (CVE-2026-41299)
slug: 2026-04-openclaw-auth-bypass
description: OpenClaw before 2026.3.28 contains an authorization bypass vulnerability in the chat.send gateway method that allows authenticated operator clients to spoof ACP identity labels and inject reserved provenance fields, leading to potential privilege escalation.
date: "2026-04-21T00:16:30Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - authorization-bypass
  - privilege-escalation
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-41299
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41299
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-6xg4-82hv-cp6f
  - https://www.vulncheck.com/advisories/openclaw-client-identity-spoofing-in-chat-send-gateway-provenance-guard
rules:
  - title: Detect OpenClaw ACP Identity Spoofing via WebSocket
    description: Detects potential ACP identity spoofing attempts during WebSocket handshake by monitoring client metadata for suspicious patterns related to reserved provenance fields.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555.004
    data_sources:
      - webserver
      - linux
  - title: Detect OpenClaw Chat Send Gateway Abuse
    description: Detects abuse of the chat.send gateway by monitoring for unusual message origins or content patterns indicative of exploitation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw, a chat application, is vulnerable to an authorization bypass (CVE-2026-41299) affecting versions prior to 2026.3.28. This vulnerability resides in the `chat.send` gateway method, where access control policies (ACP) are enforced based on client-provided metadata obtained during the WebSocket handshake. Instead of relying on verified authorization states, the system trusts self-declared metadata, enabling malicious authenticated operator clients to impersonate ACP identities and inject reserved provenance fields that should be exclusive to the ACP bridge. This flaw allows attackers to bypass intended security restrictions and potentially elevate their privileges within the OpenClaw system. The vulnerability was reported by VulnCheck on April 20, 2026, and poses a significant risk to the confidentiality and integrity of OpenClaw deployments.

## Attack Chain

1. An attacker authenticates to the OpenClaw chat system as a regular operator.
2. The attacker establishes a WebSocket connection to the `chat.send` gateway.
3. During the WebSocket handshake, the attacker crafts malicious client metadata to spoof an ACP identity.
4. The attacker injects reserved provenance fields intended for the ACP bridge within the crafted metadata.
5. The `chat.send` method incorrectly trusts the self-declared client metadata without proper authorization checks.
6. The system processes the attacker's chat message as if it originated from a trusted ACP source.
7. The attacker successfully bypasses intended authorization controls due to the spoofed identity and injected fields.
8. The attacker leverages the elevated privileges to perform unauthorized actions, such as accessing sensitive data or modifying system configurations.

## Impact

Successful exploitation of CVE-2026-41299 allows an authenticated operator client to bypass authorization controls within OpenClaw. This can lead to privilege escalation, enabling unauthorized access to sensitive information and system functionalities. The vulnerability could be exploited to inject malicious content into chat streams, disrupt communications, or compromise the integrity of the OpenClaw system. The number of potential victims is dependent on the number of OpenClaw deployments that have not been patched to version 2026.3.28 or later.

## Recommendation

*   Upgrade OpenClaw to version 2026.3.28 or later to patch CVE-2026-41299.
*   Implement additional server-side validation and authorization checks on incoming messages to verify the legitimacy of client identities and provenance fields.
*   Monitor WebSocket handshake traffic for suspicious client metadata indicative of ACP identity spoofing attempts. Deploy the Sigma rule `Detect OpenClaw ACP Identity Spoofing via WebSocket` to detect potentially malicious connections.
*   Review and harden the configuration of the `chat.send` gateway to restrict access to sensitive functionalities based on verified authorization states.
*   Regularly audit OpenClaw deployments for misconfigurations and vulnerabilities to prevent potential exploitation.
