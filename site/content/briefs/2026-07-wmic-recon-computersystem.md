---
title: Computer System Reconnaissance Via Wmic.EXE
slug: 2026-07-wmic-recon-computersystem
description: This brief details the use of `wmic.exe` with the `computersystem` flag for reconnaissance, a technique observed in campaigns by adversaries such as DEV-0270 (Phosphorus), to gather system information like domain, username, and model.
date: "2026-07-03T14:45:54Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - DEV-0270
  - APT35
  - Charming Kitten
  - TA453
  - Mint Sandstorm
  - Phosphorus
tags:
  - discovery
  - reconnaissance
  - windows
  - ransomware
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: Detects execution of wmic utility with the 'computersystem' flag in order to obtain information about the machine such as the domain, username, model, etc.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_wmic_recon_computersystem.yml
  - https://www.microsoft.com/security/blog/2022/09/07/profiling-dev-0270-phosphorus-ransomware-operations/
rules:
  - title: Computer System Reconnaissance Via Wmic.EXE
    description: Detects execution of wmic utility with the 'computersystem' flag to obtain machine information such as domain, username, and model, a technique used by groups like DEV-0270 (Phosphorus).
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

Adversaries, notably groups like DEV-0270 (also known as Phosphorus), leverage the native Windows Management Instrumentation Command-line (WMIC) utility for system reconnaissance. This technique involves executing `wmic.exe` with the `computersystem` flag to query for detailed machine information. This activity, observed since at least late 2022, serves as a crucial precursor to subsequent attack stages in ransomware operations. By gathering data such as domain membership, current username, system model, and operating system details, attackers can tailor their approach for privilege escalation, lateral movement, or targeted data exfiltration. The use of a legitimate system binary makes this activity harder to detect without specific command-line logging and careful analysis.

## Attack Chain

1.  **Reconnaissance Command Execution**: An attacker executes `wmic.exe` with the `computersystem` class to enumerate system properties.
2.  **Information Gathering**: The command `wmic computersystem get` or similar is run to extract details such as the computer's domain, username, manufacturer, model, and OS version.
3.  **Data Collection**: The collected system information is often stored temporarily on the compromised host or directly transmitted to the attacker's command and control (C2) infrastructure.
4.  **Decision Making**: Based on the gathered information, the adversary makes decisions regarding the next steps in their campaign, such as identifying targets for lateral movement or specific privilege escalation techniques.
5.  **Preparation for Exploitation**: The reconnaissance data informs the deployment of additional tools or the exploitation of specific vulnerabilities relevant to the discovered system configuration.
6.  **Further Attack Phases**: The adversary proceeds with privilege escalation, lateral movement, data exfiltration, or the deployment of payloads like ransomware, as observed in DEV-0270 operations.

## Impact

The direct impact of `wmic.exe` reconnaissance is information disclosure, which itself is low-risk. However, as demonstrated by ransomware operators like DEV-0270 (Phosphorus), this type of reconnaissance is a foundational step enabling more severe impacts. Successful information gathering allows attackers to tailor highly effective follow-on attacks, such as deploying ransomware, exfiltrating sensitive data, or causing significant operational disruption. Without detecting and mitigating these initial reconnaissance activities, organizations face a heightened risk of full system compromise, data breaches, and financial losses due to ransomware demands and recovery efforts.

## Recommendation

*   Deploy the "Computer System Reconnaissance Via Wmic.EXE" Sigma rule to your SIEM to detect suspicious `wmic.exe` usage.
*   Ensure Sysmon (Event ID 1) or equivalent process creation logging is enabled for all Windows endpoints to capture command-line arguments for `wmic.exe`.
*   Tune the "Computer System Reconnaissance Via Wmic.EXE" rule to establish a baseline of legitimate `wmic` usage in your environment and minimize false positives.
*   Monitor for other forms of system information discovery, as attackers often combine various reconnaissance techniques.
