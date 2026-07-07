---
title: Coder SSH Config Injection Vulnerability (CVE-2026-55427)
slug: 2026-07-coder-ssh-config-injection
description: A malicious or compromised Coder server can exploit CVE-2026-55427 to inject unsanitized SSH configuration values via `coder config-ssh` into developer workstations, enabling arbitrary code execution on client machines.
date: "2026-07-06T20:55:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ssh
  - configuration-injection
  - rce
  - supply-chain
  - developer-tools
  - vulnerability
vendors:
  - Coder
products:
  - Coder (>= 2.34.0, < 2.34.2)
  - Coder (>= 2.33.0, < 2.33.8)
  - Coder (>= 2.30.0, < 2.32.7)
  - Coder (< 2.29.17)
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: inject a directive such as `ProxyCommand` and achieve arbitrary code execution on any developer workstation
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-mcqq-fqgf-rxwm
---

The `coder config-ssh` utility from Coder is vulnerable to a critical configuration injection issue, tracked as CVE-2026-55427. This vulnerability allows a malicious or compromised Coder server to inject arbitrary SSH configuration directives, such as `ProxyCommand`, into a developer's `~/.ssh/config` file. This occurs because `coder config-ssh` unsafely writes server-supplied values like `HostnameSuffix` and `SSHConfigOptions` without proper sanitization of newlines or restriction of directives. If a developer runs `coder config-ssh` while connected to such a server, it can lead to arbitrary code execution on their workstation with local user privileges. The vulnerability affects Coder versions prior to v2.34.2, v2.33.8, v2.32.7, and v2.29.17. The issue, independently disclosed by Anthropic's Security Team (ANT-2026-22437), highlights a potential supply chain risk through developer tooling.

## Attack Chain

1.  **Initial Access / Server Compromise**: An attacker gains control over a Coder server deployment or compromises its administrative interface, or a Coder server administrator acts maliciously.
2.  **Configuration Injection**: The attacker modifies the Coder server's `HostnameSuffix` or `SSHConfigOptions` settings to include malicious SSH directives (e.g., `ProxyCommand` followed by a shell command) that exploit the lack of input sanitization.
3.  **Client-Side Configuration Request**: A developer executes `coder config-ssh` on their workstation (typically Linux or macOS) to configure SSH access to Coder workspaces.
4.  **Malicious Configuration Download**: The `coder config-ssh` utility fetches the unsanitized configuration values from the compromised Coder server.
5.  **Local SSH Config Modification**: `coder config-ssh` writes the received malicious `HostnameSuffix` and `SSHConfigOptions` directly into the developer's `~/.ssh/config` file, injecting the attacker-controlled SSH directives.
6.  **Triggering Execution**: The developer subsequently initiates an SSH connection to any host that leverages the newly modified `~/.ssh/config`.
7.  **Arbitrary Code Execution**: The injected `ProxyCommand` (or similar directive) within `~/.ssh/config` triggers the execution of the attacker's arbitrary code on the developer's workstation, operating with the privileges of the local user.

## Impact

Successful exploitation of CVE-2026-55427 grants attackers arbitrary code execution capabilities on developer workstations. The injected commands run with the privileges of the local user, allowing for a wide range of malicious activities including data exfiltration, installation of malware, establishment of persistence, or further lateral movement within the developer's environment. Crucially, the malicious configuration applies to all SSH connections originating from the workstation, not just those related to Coder workspaces, broadening the scope of impact significantly. While no specific victim count is available, the vulnerability poses a substantial supply chain risk to organizations leveraging the Coder platform, as compromising a single Coder server could lead to compromise of numerous developer endpoints.

## Recommendation

*   Patch CVE-2026-55427 on all affected Coder server deployments to versions v2.34.2, v2.33.8, v2.32.7, or v2.29.17 immediately.
*   Educate developers to review the output of `coder config-ssh --dry-run` before applying configuration changes to visually identify unexpected SSH directives.
*   Implement file integrity monitoring on `~/.ssh/config` files on developer workstations to detect unauthorized or suspicious modifications (e.g., via `file_event` logging).
