---
title: Multiple Vulnerabilities in Microsoft Cloud Products Allow Privilege Escalation and Code Execution
slug: 2026-04-microsoft-cloud-vulns
description: Multiple vulnerabilities in Microsoft Azure, Microsoft 365 Copilot, Microsoft Dynamics 365, and Microsoft Power Apps could allow an attacker to escalate privileges, execute arbitrary code, and conduct spoofing attacks.
date: "2026-04-24T09:09:09Z"
severities:
  - high
tags:
  - cloud
  - privilege-escalation
  - code-execution
  - spoofing
vendors:
  - Microsoft
products:
  - Azure
  - Microsoft 365 Copilot
  - Dynamics 365
  - Power Apps
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Defense Evasion
    technique_id: T1598
    technique_name: Phishing for Information
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1256
rules:
  - title: Detect Suspicious Azure Resource Creation
    description: Detects the creation of suspicious Azure resources which may indicate malicious activity following privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Microsoft 365 Copilot Application Consent Granting
    description: Detects potentially malicious consent granting to applications in Microsoft 365 Copilot.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1526
    data_sources:
      - o365
      - o365
  - title: Dynamics 365 Spoofing Attempt via Email
    description: Detects potential spoofing attempts within Dynamics 365 by monitoring for suspicious email activity.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1598
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Multiple vulnerabilities have been reported affecting Microsoft Azure, Microsoft 365 Copilot, Microsoft Dynamics 365, and Microsoft Power Apps. Successful exploitation of these vulnerabilities could enable attackers to perform a variety of malicious actions, including escalating their privileges within the affected systems, executing arbitrary code to gain further control, and conducting spoofing attacks to deceive users or bypass security measures. The full details regarding specific…
