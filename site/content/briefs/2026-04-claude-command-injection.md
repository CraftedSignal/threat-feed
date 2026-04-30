---
title: Anthropic Claude Code CLI/SDK OS Command Injection Vulnerability
slug: 2026-04-claude-command-injection
description: CVE-2026-35022 describes an OS command injection vulnerability in the Anthropic Claude Code CLI and Claude Agent SDK that allows attackers with control over authentication settings to execute arbitrary commands, potentially leading to credential theft and environment variable exfiltration.
date: "2026-04-06T20:16:25Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - command-injection
  - cve-2026-35022
  - anthropic
  - claude
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2026-35022
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35022
rules:
  - title: Detect Claude CLI/SDK Command Injection via Shell Metacharacters
    description: Detects command injection attempts in the Anthropic Claude CLI or SDK by identifying shell metacharacters in process command lines originating from the CLI or SDK.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - windows
  - title: Detect Claude CLI/SDK Configuration File Modification
    description: Detects modifications to configuration files associated with the Anthropic Claude CLI or SDK.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The Anthropic Claude Code CLI and Claude Agent SDK are vulnerable to OS command injection (CVE-2026-35022). This vulnerability stems from the insecure execution of authentication helper configuration values. Specifically, the application executes commands using `shell=true` without proper input validation on parameters such as `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, and `gcpAuthRefresh`. An attacker who can manipulate these authentication settings can inject shell metacharacters to execute arbitrary commands with the privileges of the user or automation environment running the Claude CLI or SDK. This can lead to credential theft and the exfiltration of sensitive environment variables. Defenders should focus on detecting attempts to modify authentication settings or the execution of commands originating from the Claude CLI or SDK with suspicious arguments.

## Attack Chain

1. An attacker gains unauthorized access to the configuration settings of the Anthropic Claude Code CLI or Claude Agent SDK. This could be achieved through compromised credentials or a separate vulnerability.
2. The attacker modifies the `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, or `gcpAuthRefresh` parameters within the authentication configuration.
3. The attacker injects shell metacharacters (e.g., `;`, `|`, `&&`) into these parameters, crafting malicious commands.
4. The Claude CLI or SDK attempts to authenticate, executing the configured helper command using `shell=true`.
5. The injected shell metacharacters cause the operating system to execute the attacker's malicious commands.
6. The attacker's commands steal credentials stored on the system.
7. The attacker's commands exfiltrate sensitive environment variables to an external server.
8. The attacker uses the stolen credentials and environment variables to gain further access to the victim's systems or data.

## Impact

Successful exploitation of CVE-2026-35022 allows attackers to execute arbitrary commands on the system running the Anthropic Claude Code CLI or Claude Agent SDK. This can lead to the theft of sensitive credentials, such as API keys and AWS credentials, and the exfiltration of environment variables containing sensitive information. The impact includes unauthorized access to cloud resources, data breaches, and potential supply chain compromise if the compromised environment is used for software development or deployment. The scope of the impact depends on the permissions of the user or automation environment running the vulnerable software.

## Recommendation

*   Monitor process execution for suspicious commands originating from the Claude CLI or SDK with command-line arguments containing shell metacharacters. Implement the Sigma rule "Detect Claude CLI/SDK Command Injection via Shell Metacharacters".
*   Implement strict access control policies to limit who can modify the configuration settings of the Claude CLI or SDK.
*   Regularly audit the configuration settings of the Claude CLI or SDK for any unauthorized changes.
*   Patch CVE-2026-35022 as soon as a patch is available from Anthropic.
