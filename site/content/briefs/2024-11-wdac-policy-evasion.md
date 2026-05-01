---
title: WDAC Policy File Creation by Unusual Process
slug: 2024-11-wdac-policy-evasion
description: Adversaries may use a specially crafted Windows Defender Application Control (WDAC) policy to restrict the execution of security products, detected by unusual process creation of WDAC policy files.
date: "2024-11-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wdac
  - defense-evasion
  - windows
vendors:
  - Microsoft
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Microsoft Defender XDR
  - SentinelOne Cloud Funnel
  - Elastic Defend
  - Windows Defender Application Control
  - Crowdstrike FDR
  - Sysmon
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/logangoins/Krueger/tree/main
  - https://beierle.win/2024-12-20-Weaponizing-WDAC-Killing-the-Dreams-of-EDR/
rules:
  - title: WDAC Policy File Creation by Unusual Process
    description: Detects the creation of WDAC policy files (.p7b or .cip) by processes other than known servicing components.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - file_event
      - windows
  - title: WDAC Policy File Creation in CodeIntegrity by Uncommon Process
    description: Detects WDAC policy creation by uncommon processes in the CodeIntegrity directory
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562
    data_sources:
      - file_event
      - windows
rules_count: 2
---

Attackers are increasingly targeting Windows Defender Application Control (WDAC) to disable or weaken endpoint defenses. By crafting malicious WDAC policies, adversaries can block legitimate security software and evade detection. This technique involves creating WDAC policy files (.p7b or .cip) in protected system directories using unauthorized processes. The activity often occurs when attackers have already gained a foothold in the system and are attempting to solidify their position. Successful deployment of a malicious WDAC policy can significantly hinder incident response and allow malware to operate undetected. This tactic has gained traction since late 2024, with offensive tools like Krueger demonstrating the potential for weaponizing WDAC against EDR solutions.

## Attack Chain

1.  **Initial Access:** The attacker gains initial access to the system through methods such as phishing or exploiting a software vulnerability.
2.  **Privilege Escalation:** The attacker escalates privileges to gain administrative access, which is required to modify WDAC policies.
3.  **Policy Creation:** The attacker crafts a malicious WDAC policy using tools or scripts. This policy is designed to block specific security products or processes.
4.  **Staging:** The malicious policy is staged in a temporary location on the system, often within user-writable directories.
5.  **Policy Placement:** The attacker moves the malicious WDAC policy file (.p7b or .cip) to a protected system directory, such as `C:\Windows\System32\CodeIntegrity\` or `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\`. The tool used may be a Living-off-the-Land Binary (LOLBin) or a custom .NET assembly.
6.  **Activation:** The attacker triggers the activation of the new WDAC policy, which often requires a system reboot or the use of a service control utility.
7.  **Defense Evasion:** Once the policy is active, the targeted security products are blocked, allowing the attacker to operate with reduced risk of detection.
8.  **Lateral Movement/Objectives:** With defenses weakened, the attacker can move laterally within the network, exfiltrate data, or achieve other objectives.

## Impact

A successful attack targeting WDAC can severely impair an organization's ability to detect and respond to threats. By blocking security software, attackers can operate with impunity, leading to data breaches, financial losses, and reputational damage. Observed damage includes disabled endpoint detection and response (EDR) solutions, allowing ransomware and other malware to execute without interference. The scope of impact can range from individual workstations to entire domains, depending on the breadth of the WDAC policy deployment.

## Recommendation

*   Deploy the "WDAC Policy File by an Unusual Process" Sigma rule to your SIEM to detect unauthorized WDAC policy modifications.
*   Monitor file creation events with extensions .p7b and .cip in `C:\Windows\System32\CodeIntegrity\` and `C:\Windows\System32\CodeIntegrity\CiPolicies\Active\` directories, specifically filtering for processes other than `poqexec.exe`, `TiWorker.exe`, and `omadmclient.exe`.
*   Enable Sysmon Event ID 11 (File Create) logging to capture file creation events and provide the necessary data for the Sigma rule to function effectively.
*   Implement strict access control policies on WDAC policy directories to prevent unauthorized modification.
