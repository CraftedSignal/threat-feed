---
title: OpenClaw PowerShell Encoded-Command Alias Bypass Vulnerability
slug: 2026-07-openclaw-powershell-alias-bypass
description: A high-severity vulnerability (GHSA-j472-gf56-x589) in OpenClaw allows an attacker to bypass allowlist checks for PowerShell encoded commands by using abbreviated encoded-command flags, leading to unauthorized code execution on the underlying Windows system if a vulnerable feature is enabled and reachable.
date: "2026-07-03T12:12:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - code-execution
  - powershell
  - bypass
  - openclaw
  - npm
  - windows
vendors:
  - OpenClaw
products:
  - OpenClaw (<= 2026.5.7)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: a command request using abbreviated encoded-command flags could use an alias form not recognized by the allowlist parser... this could run encoded PowerShell content
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: PowerShell encoded-command aliases could miss exec allowlist checks
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-j472-gf56-x589
rules:
  - title: Detect Suspicious PowerShell Encoded Command Execution
    description: Detects potential execution of unvetted PowerShell commands, relevant to the OpenClaw GHSA-j472-gf56-x589 vulnerability, by identifying processes executing PowerShell with encoded command flags. This helps identify the result of the allowlist bypass.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1027
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

A critical vulnerability (GHSA-j472-gf56-x589) has been identified in the npm/openclaw package, affecting versions up to `2026.5.7`. This flaw allows PowerShell encoded-command aliases to circumvent security allowlist checks within the OpenClaw application. Specifically, when an attacker provides crafted input containing PowerShell commands with abbreviated encoded-command flags, the OpenClaw allowlist parser fails to recognize these alias forms, permitting the execution of unvetted PowerShell content. This bypass poses a significant risk to organizations using OpenClaw, as it enables unauthorized code execution on the underlying Windows operating system, potentially leading to system compromise, data exfiltration, or further network penetration if the affected feature is enabled, reachable by lower-trust input, and improperly configured.

## Attack Chain

1.  **Crafted Input Delivery**: An attacker identifies an enabled and reachable OpenClaw feature that accepts command requests.
2.  **Payload Injection**: The attacker sends a crafted input to this feature, embedding PowerShell commands that utilize abbreviated encoded-command flags (e.g., `-e` instead of `-EncodedCommand`).
3.  **Allowlist Bypass**: OpenClaw's internal allowlist parser, designed to vet PowerShell commands, fails to properly recognize the abbreviated alias form of the encoded command flags.
4.  **Unvetted Command Execution**: Due to the parsing failure, the embedded encoded PowerShell content bypasses the intended security allowlist checks.
5.  **PowerShell Process Launch**: OpenClaw executes the unvetted, encoded PowerShell command on the underlying Windows operating system.
6.  **Code Execution**: The malicious PowerShell script performs attacker-defined actions, such as downloading and executing additional malware, establishing persistence, or exfiltrating sensitive data.
7.  **Impact Achieved**: The attacker gains unauthorized code execution capabilities within the OpenClaw environment and potentially on the host system.

## Impact

The successful exploitation of this vulnerability can lead to unauthorized arbitrary code execution on the underlying Windows operating system hosting the OpenClaw application. The practical impact is highly dependent on the specific configuration of the OpenClaw instance and whether lower-trust or untrusted input sources can reach the vulnerable features. If an attacker can leverage this bypass, they could potentially compromise the entire host system, exfiltrate sensitive data processed by OpenClaw, or establish a foothold for further attacks within the organization's network. There are no specific victim counts or targeted sectors mentioned, but any organization using vulnerable versions of OpenClaw configured with reachable features accepting external input is at risk.

## Recommendation

*   Upgrade the `npm/openclaw` package to version `2026.5.12` or later immediately to patch the vulnerability.
*   As a temporary mitigation, avoid allowlisting PowerShell wrapper forms and require explicit approval for any encoded PowerShell commands until patching is complete.
*   Disable the affected OpenClaw features entirely if they are not strictly needed, reducing the attack surface.
*   Deploy the Sigma rule provided in this brief to your SIEM to detect suspicious PowerShell encoded command execution on Windows hosts where OpenClaw is deployed.
*   Enable comprehensive logging for PowerShell activity, including script block logging and module logging, to enhance visibility for the detection rule.
