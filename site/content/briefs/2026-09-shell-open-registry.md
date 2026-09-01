---
title: Abuse of Shell Open Registry Keys for Persistence and UAC Bypass
slug: 2026-09-shell-open-registry
description: Adversaries manipulate Windows shell open command registry keys to facilitate User Account Control (UAC) bypass and establish persistence through file association hijacking.
date: "2026-09-01T12:07:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - privilege-escalation
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1546.001
    technique_name: Component Object Model Hijacking
    evidence: Detects manipulation of shell open command registry keys... to establish persistence through file association hijacking.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.002
    technique_name: Bypass User Account Control
    evidence: Detects manipulation of shell open command registry keys such as 'ms-settings'... which are commonly abused to achieve UAC bypass.
    confidence_band: high
references:
  - https://github.com/hfiref0x/UACME
  - https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/
  - https://github.com/RhinoSecurityLabs/Aggressor-Scripts/tree/master/UACBypass
  - https://tria.ge/211119-gs7rtshcfr/behavioral2
rules:
  - title: Detect Shell Open Registry Keys Manipulation
    description: Detects manipulation of shell open command registry keys commonly abused for UAC bypass or persistence.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1546.001
      - T1548.002
    data_sources:
      - registry_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to detect registry modifications to ms-settings and exefile paths.
      owner: Detection Engineering
      due: 24h
      evidence: Rule provided in source.
  hunt_leads:
    - lead: Search for unauthorized SetValue events on shell open command keys in registry audit logs.
      technique_id: T1548.002
      data_needed:
        - Registry modification logs (EID 12/13/14)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source explicitly identifies these keys as high-value for bypass and persistence.
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict GPOs or EDR policies to restrict modifications to Classes and shell-related registry keys.
      owner: IT Operations
      addresses: T1548.002
      evidence: Registry abuse is the primary mechanism of this threat.
---

Windows shell open registry keys, specifically those under "ms-settings" and "exefile", represent a critical surface for privilege escalation and persistence. Attackers manipulate these keys to hijack file associations or exploit high-integrity processes that trust these registry locations, such as fodhelper.exe. By injecting custom commands or symbolic links into these paths, attackers can force the operating system to execute arbitrary payloads with elevated privileges or upon specific system triggers. This technique is well-documented in UAC bypass research and has been observed in various malware campaigns, including infostealers like Lokibot. Defenders must monitor these registry paths for unauthorized modifications, as they are rarely changed by legitimate administrative activity.

## Attack Chain

1. Attacker gains initial access to the target system as a low-privileged user.
2. Attacker identifies a target registry key (e.g., HKCU\Software\Classes\ms-settings\shell\open\command) for manipulation.
3. Attacker modifies the "(Default)" value or adds a "DelegateExecute" entry to the targeted registry key.
4. Attacker inserts a path to a malicious executable or a command string into the registry value.
5. Attacker triggers a legitimate high-integrity process (e.g., fodhelper.exe) that queries the hijacked registry key.
6. The system executes the attacker-controlled path due to the hijacked association.
7. Attacker achieves local privilege escalation or established persistence under the security context of the triggered process.

## Impact

Successful manipulation of these keys allows adversaries to bypass UAC prompts, enabling them to execute malicious code in high-integrity contexts without user consent. This capability is frequently used to escalate privileges, deploy persistent backdoors, and maintain long-term access to compromised systems, significantly increasing the risk of widespread data exfiltration and ransomware deployment.

## Recommendation

Deploy the provided Sigma rule to monitor for unauthorized modifications to shell open registry keys. Prioritize alerting on writes to the specified paths, excluding known-good COM object CLSIDs that are used by legitimate system functions.
