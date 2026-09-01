---
title: Potential System Persistence via AutodialDLL Registry Modification
slug: 2026-09-persistence-autodialdll
description: Adversaries can achieve persistence by modifying the AutodialDLL registry key to load a malicious DLL through the Windows Winsock2 library.
date: "2026-09-01T12:28:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - windows
  - registry
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Modifying the AutodialDLL registry key acts as a persistence method to load custom DLLs via the Winsock2 library.
    confidence_band: high
references:
  - https://www.hexacorn.com/blog/2015/01/13/beyond-good-ol-run-key-part-24/
  - https://persistence-info.github.io/Data/autodialdll.html
rules:
  - title: Detect Potential Persistence Via AutodialDLL
    description: Detects modifications to the AutodialDLL registry key, which can be used to load a custom DLL via the Winsock2 library.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma detection rule to the SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific registry path for detection.
  hunt_leads:
    - lead: Search historical registry modification logs for the AutodialDLL path.
      technique_id: T1547
      data_needed:
        - Event ID 13 (Registry Set)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Technique is known to be used for persistence.
---

Persistence on Windows systems can be achieved by abusing the AutodialDLL functionality within the Winsock2 configuration. The AutodialDLL registry key allows an administrator to specify a DLL that is loaded by the Winsock2 library when network functions are called. By modifying this key to point to a attacker-controlled DLL, a malicious actor can force the system to execute arbitrary code with the privileges of the process calling Winsock2 functions. This technique effectively hijacks the loading process, ensuring the malicious code executes whenever the networking stack is initialized. Since this behavior is rarely utilized by legitimate software, any modification to this registry path should be treated as a potential indicator of malicious persistence or credential harvesting attempts.

## Impact

Successful exploitation of this persistence mechanism allows for arbitrary code execution with the context of any process that utilizes Winsock2, potentially leading to privilege escalation, system-wide persistence, and stealthy malware execution that evades traditional process-based monitoring.

## Recommendation

- Deploy the provided Sigma rule to monitor for any write operations to the AutodialDLL registry path.
- Baseline existing legitimate AutodialDLL configurations in your environment to identify deviations.
- Enable Windows Registry auditing (SACLs) for the HKLM\SYSTEM\CurrentControlSet\Services\WinSock2\Parameters registry key to ensure visibility.
