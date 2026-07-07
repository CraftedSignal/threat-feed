---
title: Potentially Suspicious WDAC Policy File Creation
slug: 2026-07-suspicious-wdac-policy-creation
description: Attackers may create Windows Defender Application Control (WDAC) policy files from abnormal processes to bypass Endpoint Detection and Response (EDR) or Antivirus (AV) solutions while allowing their own malicious code to execute on compromised Windows systems, impacting defense capabilities.
date: "2026-07-03T13:49:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-impairment
  - wdac
  - application-control
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Detects suspicious Windows Defender Application Control (WDAC) policy file creation from abnormal processes that could be abused by attacker to block EDR/AV components while allowing their own malicious code to run on the system.
    confidence_band: high
references:
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-using-group-policy
  - https://beierle.win/2024-12-20-Weaponizing-WDAC-Killing-the-Dreams-of-EDR/
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/appcontrol-deployment-guide
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-with-script
  - https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/deploy-appcontrol-policies-with-memcm
rules:
  - title: Potentially Suspicious WDAC Policy File Creation
    description: Detects the creation of Windows Defender Application Control (WDAC) policy files from abnormal processes, which could be abused by an attacker to block EDR/AV components while allowing their own malicious code to run on the system.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

This threat brief details a technique where attackers create or modify Windows Defender Application Control (WDAC) policies from non-standard or unauthorized processes. WDAC is a security feature in Windows designed to control which applications are allowed to run on a system. While legitimate processes (like PowerShell, Configuration Manager, or WDAC Wizard) typically manage these policies, an adversary gaining initial access could abuse this mechanism. By crafting and deploying a malicious WDAC policy, an attacker can effectively disable or bypass existing security controls, such as EDR or AV solutions, by whitelisting their own malicious payloads and blacklisting security agent components. This allows the attacker to execute their tools unimpeded, significantly impairing the victim's ability to detect and respond to ongoing intrusions. The detection focuses on file creation events in the `C:\Windows\System32\CodeIntegrity\` directory by processes not typically associated with WDAC policy management.

## Impact

Successful exploitation of this technique can lead to a significant degradation of endpoint security posture. By weaponizing WDAC policies, attackers can bypass security software, allowing for unimpeded execution of malware, credential theft, data exfiltration, or further lateral movement. The primary impact is the loss of visibility and control for security teams, rendering installed EDR/AV solutions ineffective and increasing the risk of widespread compromise or data breaches without immediate detection.

## Recommendation

*   Deploy the Sigma rule "Potentially Suspicious WDAC Policy File Creation" provided in this brief to your SIEM and tune for your environment to detect unauthorized WDAC policy modifications.
*   Regularly review file creation events in `C:\Windows\System32\CodeIntegrity\` for anomalies not covered by the `filter_main_*` exclusions in the provided Sigma rule.
*   Implement strong access controls and principle of least privilege to prevent unauthorized processes from writing to critical system directories.
*   Monitor for any unexpected changes to WDAC policies via Group Policy or other management tools, especially those that block security software.
