---
title: PraisonAI AICoder Component Vulnerabilities Allow Arbitrary File Write and Command Execution (CVE-2026-61445)
slug: 2026-07-praisonai-rce
description: PraisonAI versions prior to 4.6.78 are vulnerable to arbitrary file write and command execution (CVE-2026-61445) in its AICoder component due to missing path validation and command sanitization, allowing attackers to inject malicious prompts via the chat interface to achieve root-level shell command execution.
date: "2026-07-11T14:18:45Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - arbitrary-file-write
  - command-execution
  - ai
  - llm
  - path-traversal
vendors:
  - MervinPraison
products:
  - PraisonAI (< 4.6.78)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can inject malicious prompts through the chat interface to write files to arbitrary filesystem locations and execute arbitrary shell commands with root privileges.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: execute arbitrary shell commands with root privileges.
    confidence_band: high
cves:
  - id: CVE-2026-61445
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61445
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-9mp3-24cc-77mg
  - https://www.vulncheck.com/advisories/praisonai-before-arbitrary-file-write-and-command-execution
---

CVE-2026-61445 identifies critical arbitrary file write and command execution vulnerabilities within the AICoder component of PraisonAI, affecting all versions prior to 4.6.78. The flaw stems from insufficient path validation and command sanitization during LLM tool calls, which PraisonAI performs. Attackers can exploit this by injecting specially crafted, malicious prompts through the PraisonAI chat interface. Successful exploitation grants an attacker the ability to write files to arbitrary locations on the filesystem and execute arbitrary shell commands with root privileges on the underlying system. This allows for full system compromise, including data exfiltration, service disruption, and the establishment of persistence. Defenders should prioritize patching this vulnerability immediately to prevent unauthorized access and control over affected PraisonAI instances.

## Attack Chain

1. Attacker identifies and gains access to a PraisonAI chat interface that uses the vulnerable AICoder component.
2. Attacker crafts a malicious prompt incorporating specific directives designed to trigger an LLM tool call within PraisonAI.
3. The crafted prompt contains either path traversal sequences (e.g., `../`) or shell metacharacters (e.g., `;`, `|`, `$(command)`) embedded within the parameters for the LLM tool call.
4. PraisonAI's AICoder component processes the malicious prompt and attempts to execute the LLM tool call without performing proper input validation or command sanitization.
5. Due to missing path validation, the crafted input allows the attacker to specify and write to arbitrary file system locations on the host system.
6. Concurrently, due to missing command sanitization, the crafted input enables the attacker to inject and execute arbitrary shell commands.
7. The injected shell commands are executed by the PraisonAI application process with root privileges, granting the attacker full control over the compromised system.
8. Attacker leverages the root-level command execution capability for further actions, such as establishing persistence, exfiltrating sensitive data, or causing system disruption.

## Impact

Successful exploitation of CVE-2026-61445 leads to critical consequences, as attackers gain the ability to write arbitrary files and execute commands with root privileges on the compromised system. This level of access allows for complete system compromise, enabling activities such as data theft, unauthorized system configuration changes, installation of backdoors for persistence, and disruption of services. While no specific victim counts or targeted sectors are detailed in the NVD, any organization utilizing PraisonAI versions before 4.6.78 is at risk of severe operational and data security breaches if this vulnerability is exploited.

## Recommendation

* Patch CVE-2026-61445 by updating PraisonAI to version 4.6.78 or later immediately to remediate the arbitrary file write and command execution vulnerabilities.
* Implement web application firewall (WAF) rules to detect and block chat interface inputs containing suspicious shell metacharacters (e.g., `;`, `|`, `&`, `$(`) or file path traversal attempts (e.g., `../`, `..\`), specifically referenced in the Attack Chain.
* Monitor application and system logs for unusual process creation originating from the PraisonAI application's user, especially the execution of shell interpreters (`sh`, `bash`) or system utilities (`wget`, `curl`, `chmod`, `chown`) with root privileges, as detailed in the Attack Chain.
