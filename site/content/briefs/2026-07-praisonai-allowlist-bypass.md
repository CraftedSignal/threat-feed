---
title: 'CVE-2026-61434: PraisonAI Shell Command Allowlist Bypass'
slug: 2026-07-praisonai-allowlist-bypass
description: PraisonAI versions prior to 4.6.78 contain an allowlist bypass vulnerability in shell command execution that allows attackers to use find's built-in -exec, -execdir, and -delete actions to execute restricted commands, read or delete files, or run non-allowlisted binaries, bypassing existing shell metacharacter filters, which can lead to arbitrary command execution and impact system integrity.
date: "2026-07-10T15:26:32Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - praisonai
  - allowlist-bypass
  - cve
vendors:
  - MervinPraison
products:
  - PraisonAI
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: PraisonAI versions before 4.6.78 contain an allowlist bypass vulnerability in shell command execution that allows attackers to execute restricted commands via find's built-in -exec, -execdir, and -delete actions.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Attackers can craft find commands with these built-in actions to... delete files
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: Attackers can craft find commands with these built-in actions to read blocked files
    confidence_band: med
cves:
  - id: CVE-2026-61434
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-61434
  - https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-cv3g-hj65-pcfh
  - https://www.vulncheck.com/advisories/praisonai-before-allowlist-bypass-via-find-exec
iocs:
  - type: url
    value: https://github.com/MervinPraison/PraisonAI/security/advisories/GHSA-cv3g-hj65-pcfh
  - type: url
    value: https://www.vulncheck.com/advisories/praisonai-before-allowlist-bypass-via-find-exec
ioc_counts:
  url: 2
rules:
  - title: Detect PraisonAI CVE-2026-61434 Exploitation - Suspicious find Command Execution
    description: Detects CVE-2026-61434 exploitation - `find` commands containing `-exec`, `-execdir`, or `-delete` options, which can be leveraged for allowlist bypass and arbitrary command execution in vulnerable PraisonAI instances.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Attackers can exploit CVE-2026-61434, a critical allowlist bypass vulnerability in PraisonAI versions before 4.6.78. This flaw permits the execution of restricted shell commands by leveraging specific built-in actions of the `find` utility: `-exec`, `-execdir`, and `-delete`. By crafting malicious input that eventually triggers a `find` command with these parameters, threat actors can circumvent the application's existing shell metacharacter filters. This enables unauthorized operations such as reading sensitive files, deleting critical system components, or executing arbitrary, non-allowlisted binaries, potentially leading to full system compromise or data manipulation. The vulnerability was published on July 10, 2026.

## Attack Chain

1. An attacker gains initial access to a system running a vulnerable version of PraisonAI, potentially through a separate vulnerability or compromised credentials.
2. The attacker crafts specific input to the PraisonAI application that is designed to be processed by an underlying `find` command.
3. The crafted input includes `find` command syntax utilizing the built-in actions `-exec`, `-execdir`, or `-delete`.
4. The PraisonAI application, due to the allowlist bypass vulnerability, executes the crafted `find` command without properly filtering these sensitive actions.
5. The `-exec` or `-execdir` actions are used to execute arbitrary binaries or scripts not present in the application's allowlist.
6. Alternatively, the `-delete` action is used to remove critical files or directories, leading to data destruction or denial of service.
7. Successful exploitation results in arbitrary command execution, allowing the attacker to establish persistence, exfiltrate data, or further compromise the host system.

## Impact

Successful exploitation of CVE-2026-61434 grants attackers significant control over the affected system. The ability to execute arbitrary commands allows for potential full system compromise, including privilege escalation, installation of malicious software, and lateral movement within the network. Attackers can read blocked files, leading to sensitive data exfiltration, or delete critical files, resulting in data loss, system instability, or denial of service for the PraisonAI application and potentially the host system. While no specific victim numbers or targeted sectors are currently disclosed, any organization utilizing PraisonAI versions prior to 4.6.78 is at risk.

## Recommendation

* Immediately patch PraisonAI to version 4.6.78 or later to address CVE-2026-61434.
* Deploy the Sigma rule "Detect PraisonAI CVE-2026-61434 Exploitation - Suspicious find Command Execution" to your SIEM to monitor for suspicious `find` command executions on Linux systems.
* Enable comprehensive process creation logging (e.g., using Auditd or Sysmon for Linux) to provide telemetry for the detection rules.
* Implement robust input validation and sanitization for all user-supplied data processed by applications that interact with the operating system shell.
