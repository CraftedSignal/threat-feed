---
title: OpenClaw Heredoc Shell Expansion Bypass (CVE-2026-44115)
slug: 2026-05-openclaw-heredoc-bypass
description: OpenClaw before 2026.4.22 is vulnerable to shell expansion in unquoted heredoc bodies, allowing attackers to bypass exec allowlist validation and execute unauthorized commands.
date: "2026-05-06T20:16:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-44115
  - shell-expansion
  - heredoc
  - allowlist-bypass
  - incomplete-list-of-disallowed-inputs
vendors:
  - VulnCheck
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-44115
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44115
  - https://github.com/openclaw/openclaw/commit/b2e8b7d4bb2f22eaa16f5c4b07547774e90b65a5
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-x3h8-jrgh-p8jx
  - https://www.vulncheck.com/advisories/openclaw-shell-expansion-bypass-in-unquoted-heredocs-via-exec-allowlist
rules:
  - title: Detect Suspicious Heredoc Usage
    description: Detects the usage of heredocs with potentially malicious shell expansion tokens.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Command Execution via OpenClaw
    description: Detects command execution where the parent process is related to OpenClaw.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

OpenClaw before version 2026.4.22 contains an exec allowlist analysis vulnerability that allows for shell expansion within unquoted heredoc bodies. This vulnerability, identified as CVE-2026-44115, enables attackers to bypass the intended allowlist restrictions by embedding shell expansion tokens directly into the heredoc content. When OpenClaw processes these heredocs, the embedded tokens are expanded, leading to the execution of commands that would otherwise be blocked by the allowlist. This vulnerability was reported by VulnCheck and addressed in version 2026.4.22. Successful exploitation allows an attacker with low privileges to execute arbitrary commands on the system.

## Attack Chain

1.  Attacker crafts a malicious input containing an unquoted heredoc.
2.  The heredoc body includes shell expansion tokens (e.g., `${IFS}`).
3.  The attacker submits the malicious input to OpenClaw.
4.  OpenClaw processes the input and passes it to the vulnerable heredoc parsing logic.
5.  The shell expansion tokens within the heredoc body are expanded before allowlist validation.
6.  The expanded command is executed, bypassing the intended restrictions.
7.  Attacker achieves arbitrary command execution on the system.

## Impact

Successful exploitation of this vulnerability allows attackers to execute commands that should be blocked by the configured allowlist. This can lead to a variety of negative outcomes, including unauthorized access to sensitive data, modification of system configurations, or even complete system compromise. The severity is high due to the relative ease of exploitation (low privileges required) and the potential for significant impact on the affected system.

## Recommendation

*   Upgrade OpenClaw to version 2026.4.22 or later to remediate CVE-2026-44115.
*   Deploy the Sigma rule `Detect Suspicious Heredoc Usage` to identify potential exploitation attempts.
*   Monitor webserver logs for suspicious activity related to OpenClaw, and review any unusual commands being executed on the system.
