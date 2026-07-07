---
title: Hardware Model Reconnaissance Via Wmic.EXE
slug: 2026-07-hardware-model-recon-wmic
description: Adversaries leverage the built-in Windows Management Instrumentation Command-line (WMIC.EXE) utility with the `csproduct` command to perform hardware model and vendor reconnaissance on target systems, a technique observed in campaigns utilizing infostealers like Kuraystealer, enabling further tailored attacks.
date: "2026-07-03T14:47:04Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Kuraystealer
tags:
  - reconnaissance
  - windows
  - infostealer
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Kuraystealer malware can be delivered via malicious email attachments or infected software downloads, leading to initial system compromise.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1047
    technique_name: Windows Management Instrumentation
    evidence: The stealer will then leverage wmic commands to collect information from the target machine about the computer system, baseboard, processor, bios, product, and more.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Kuraystealer executes its payload, typically a .NET executable, which then calls built-in Windows commands like wmic.exe.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: The stealer will then leverage wmic commands to collect information from the target machine about the computer system, baseboard, processor, bios, product, and more.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Kuraystealer malware uses `wmic csproduct get name,vendor,version,identifyingnumber` to gather system hardware and vendor details.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Kuraystealer is a .NET infostealer that steals information and credentials from a victim’s device, archives the stolen data, and transmits it to a Discord webhook server.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wmic_recon_csproduct.yml
  - https://jonconwayuk.wordpress.com/2014/01/31/wmic-csproduct-using-wmi-to-identify-make-and-model-of-hardware/
  - https://www.uptycs.com/blog/kuraystealer-a-bandit-using-discord-webhooks
rules:
  - title: Hardware Model Reconnaissance Via Wmic.EXE
    description: Detects the execution of WMIC with the 'csproduct' command, used by adversaries for hardware model and vendor reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - execution
      - reconnaissance
    techniques:
      - T1047
      - T1082
      - T1592
      - T1592.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Adversaries, particularly groups deploying infostealers like Kuraystealer, actively leverage legitimate built-in Windows utilities to perform reconnaissance without raising immediate suspicion. One such technique involves using `wmic.exe` with the `csproduct` command to query system hardware models, vendors, and versions. This method, identified in various threat reports including those detailing Kuraystealer's operations since at least 2023, allows attackers to quickly gather crucial details about the underlying infrastructure of compromised systems. This information is vital for post-exploitation activities, enabling tailored attacks, further exploitation based on specific hardware vulnerabilities, or confirming the value of a compromised system before proceeding with data exfiltration. The reliance on a native, often whitelisted, tool like WMIC makes detection challenging for defenders without specific process command-line logging and robust correlation rules.

## Attack Chain

1.  **Initial Access**: The victim downloads and executes a malicious payload, often disguised as legitimate software, initiating the Kuraystealer infection.
2.  **Execution**: The Kuraystealer malware executes on the system, typically a .NET assembly, which then spawns child processes to perform its malicious activities.
3.  **System Information Discovery**: The malware executes `wmic.exe csproduct get name,vendor,version,identifyingnumber` to gather detailed hardware model and vendor information about the compromised machine.
4.  **Additional Reconnaissance**: Kuraystealer continues to use `wmic.exe` and other built-in commands to collect further system details, such as information about the processor, BIOS, and baseboard, to build a comprehensive system profile.
5.  **Data Collection**: The infostealer actively searches for and collects sensitive data, including credentials from web browsers, cryptocurrency wallet files, and other specified personal information from the local system.
6.  **Data Staging and Exfiltration**: Collected data is typically compressed into an archive (e.g., ZIP) and then exfiltrated to attacker-controlled infrastructure, often leveraging platforms like Discord webhooks.

## Impact

The successful execution of WMIC for reconnaissance provides attackers with valuable insights into the target system's hardware, enabling them to customize subsequent attacks or determine the value of the compromised host. In the context of infostealers like Kuraystealer, this reconnaissance precedes the theft of sensitive data, including credentials, browser history, and cryptocurrency wallet information. This leads to severe financial and reputational damage for victims, as critical information is exfiltrated and potentially sold or misused. While specific victim counts for this particular reconnaissance technique are not isolated, the broader Kuraystealer campaigns have targeted a wide range of individuals and organizations globally, resulting in significant data breaches.

## Recommendation

*   Enable Sysmon process-creation logging to capture `wmic.exe` executions and their command-line arguments, which is essential for activating the rules below.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment, paying close attention to `wmic.exe` executions that include `csproduct` in their command line.
*   Implement strong application whitelisting policies to prevent the execution of unauthorized infostealer payloads, which precede the use of `wmic.exe` for reconnaissance.
