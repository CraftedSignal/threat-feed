---
title: OpenClaw Privilege Escalation Vulnerability (CVE-2026-42432)
slug: 2026-04-openclaw-privesc
description: OpenClaw before 2026.4.8 contains a privilege escalation vulnerability that allows previously paired nodes to reconnect and execute privileged commands without proper authorization, potentially leading to complete system compromise.
date: "2026-04-28T19:37:47Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - privilege-escalation
  - cve-2026-42432
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-42432
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42432
  - https://github.com/openclaw/openclaw/commit/d7c3210cd6f5fdfdc1beff4c9541673e814354d5
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-5wj5-87vq-39xm
  - https://www.vulncheck.com/advisories/openclaw-command-escalation-via-node-pairing-reconnect-bypass
rules:
  - title: Detect OpenClaw Unauthorized Command Execution
    description: Detects command execution in OpenClaw without proper operator.admin scope after node reconnection, indicating a potential privilege escalation attempt.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - application
      - openclaw
  - title: Detect OpenClaw Node Reconnection Event
    description: Detects a node reconnection event in OpenClaw logs, which can be a precursor to exploiting CVE-2026-42432.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - application
      - openclaw
rules_count: 2
---

OpenClaw, a local assistant system, is vulnerable to a privilege escalation attack. CVE-2026-42432 affects versions prior to 2026.4.8. Attackers who have previously paired a node with the OpenClaw system can bypass re-pairing authentication. This allows them to reconnect with the ability to execute commands that should require `operator.admin` scope. The vulnerability enables unauthorized execution of privileged commands on the local assistant system, potentially leading to full system compromise.

## Attack Chain

1. An attacker initially pairs a node with the OpenClaw system, establishing a legitimate connection.
2. The OpenClaw system is upgraded to a version prior to 2026.4.8, or remains on a vulnerable version.
3. The attacker disconnects the previously paired node.
4. The attacker reconnects the node to the OpenClaw system.
5. Due to the vulnerability, the re-pairing authentication process is bypassed.
6. The attacker exploits the bypassed authentication to send commands to the OpenClaw system.
7. The OpenClaw system processes these commands as if they were authorized by an administrator.
8. The attacker executes privileged commands, gaining unauthorized control over the local assistant system.

## Impact

Successful exploitation of this vulnerability allows attackers to execute arbitrary commands with elevated privileges on the OpenClaw system. This can lead to complete compromise of the local assistant system, potentially affecting other connected devices or systems. The vulnerability could be exploited to steal sensitive data, install malware, or disrupt critical services. The impact is high due to the potential for full system takeover.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.8 or later to patch CVE-2026-42432.
*   Implement network segmentation to limit the impact of compromised OpenClaw systems.
*   Monitor OpenClaw logs for unusual command execution patterns after node reconnections, using a rule similar to the provided "Detect OpenClaw Unauthorized Command Execution" Sigma rule.
