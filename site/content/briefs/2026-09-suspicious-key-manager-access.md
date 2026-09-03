---
title: Suspicious Credential Manager Invocation
slug: 2026-09-suspicious-key-manager-access
description: Detection of an adversary technique involving the invocation of the Windows Stored User Names and Passwords dialogue to access or export cached credentials.
date: "2026-09-03T12:42:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - windows
  - rundll32
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
    evidence: Detects the invocation of the Stored User Names and Passwords dialogue (Key Manager)
    confidence_band: high
references:
  - https://twitter.com/NinjaParanoid/status/1516442028963659777
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_rundll32_keymgr.yml
rules:
  - title: Detect Suspicious Key Manager Access
    description: Detects the invocation of the Stored User Names and Passwords dialogue (Key Manager) via rundll32.exe
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555.004
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule provided in this brief to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides established detection logic
  hunt_leads:
    - lead: Search for rundll32.exe processes with command lines containing keymgr
      technique_id: T1555.004
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Technique is a known method for credential access
---

This threat brief focuses on the exploitation of the Windows Stored User Names and Passwords interface, commonly referred to as the Key Manager. Attackers leverage the rundll32.exe utility to invoke this GUI-based component via the keymgr.dll library. By executing the specific command 'rundll32.exe keymgr.dll,KRShowKeyMgr', threat actors can force the Credential Manager window to appear in the user's session. This behavior is indicative of an attempt to interact with or export saved credentials, such as website passwords, network share authentication tokens, or stored certificates, facilitating credential access and persistence efforts. Defenders should monitor for this specific command line pattern to identify unauthorized attempts to harvest stored secrets from the host system.

## Impact

Successful exploitation allows an adversary to view, modify, or potentially exfiltrate credentials stored by the Windows Credential Manager. This access can lead to lateral movement, privilege escalation, and persistent access to authenticated services, compromising the overall security posture of the targeted endpoint.

## Recommendation

Deploy the Sigma rule below to monitor for unauthorized execution of the Credential Manager dialogue. Ensure Sysmon or equivalent process-creation auditing is active, specifically capturing command-line arguments. Investigate all instances where this utility is invoked outside of known administrative configuration tasks.
