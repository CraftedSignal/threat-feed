---
title: 'CVE-2026-109560: Permission Bypass in Continue CLI'
slug: 2026-10-continue-cli-bypass
description: Continue CLI versions up to 1.5.47 are vulnerable to a command injection flaw that allows attackers to execute arbitrary commands by chaining them after permitted shell commands.
date: "2026-10-12T22:42:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:continue:continue_cli:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - cli-security
  - supply-chain
vendors:
  - Continue
products:
  - Continue CLI (<= 1.5.47)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The tool allows attackers to run unapproved commands by chaining them after allowed Bash prefix rules via shell metacharacters.
    confidence_band: high
cves:
  - id: CVE-2026-109560
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109560
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade @continuedev/cli to a version patched against CVE-2026-109560
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure
  mitigation_plan:
    - priority: immediate
      action: Upgrade @continuedev/cli to a version higher than 1.5.47
      owner: IT Operations
      addresses: CVE-2026-109560
      evidence: NVD vulnerability disclosure
---

Continue CLI (at continuedev/cli) through version 1.5.47 contains a high-severity permission bypass vulnerability (CVE-2026-109560). The vulnerability stems from improper validation of commands that the CLI tool is permitted to execute. An attacker can exploit this by injecting malicious content into repository files or web pages fetched by the CLI agent. When the agent processes these inputs, it fails to sanitize inputs effectively, allowing the injection of shell metacharacters such as ;, &&, or |. Consequently, an attacker can force the agent to append and execute arbitrary commands with the privileges of the user running the CLI tool. This vulnerability represents a significant risk to developers and automation environments utilizing the tool, as it permits unauthorized code execution via manipulated project context.

## Impact

Successful exploitation allows for arbitrary code execution in the context of the user running the Continue CLI tool. This can lead to local privilege escalation, exfiltration of sensitive source code or environment variables, and persistence within the development environment. The impact is elevated given that AI-assisted coding tools often have access to private repositories and API tokens.

## Recommendation

- Upgrade Continue CLI (@continuedev/cli) to a version beyond 1.5.47 immediately.
- Implement restrictive least-privilege policies for accounts and CI/CD pipelines that execute AI coding agents.
- Audit repository content and remote resources that the Continue CLI is configured to fetch for unexpected shell metacharacters.
