---
title: Suspicious Child Processes of consent.exe
slug: 2026-08-suspicious-consent-exe
description: Detection of unauthorized child process creation by the Windows UAC consent.exe binary, a common indicator of UAC bypass and privilege escalation activity.
date: "2026-08-07T15:15:10Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - windows
  - uac-bypass
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.002
    technique_name: 'Abuse Elevation Control Mechanism: UAC Bypass'
    evidence: Child process creation from this parent is a known indicator of UAC bypass and privilege escalation techniques.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This behavior is associated with UAC bypass exploits and has been observed in multiple post-exploitation frameworks.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This behavior is associated with UAC bypass exploits and has been observed in multiple post-exploitation frameworks.
    confidence_band: high
cves:
  - id: CVE-2024-30051
    cvss: 7.8
    epss: 0.05687
references:
  - https://securelist.com/cve-2024-30051/112618/
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_suspicious_child_process_of_consent_exe.yml
rules:
  - title: Detect Suspicious Child Process of consent.exe
    description: Detects unauthorized child processes spawned by consent.exe, which is a known indicator of UAC bypass and privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1548.002
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
    - action: Deploy Sigma rule to EDR/SIEM.
      owner: Detection Engineering
      due: 48h
      evidence: Source detection documentation.
  hunt_leads:
    - lead: Search for historical instances of consent.exe launching non-WerFault.exe processes.
      technique_id: T1548.002
      data_needed:
        - Process creation events
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Indicator of past UAC bypass attempts.
---

The Windows binary consent.exe is responsible for rendering the User Account Control (UAC) elevation dialog. Under normal operating conditions, this process should not spawn any child processes, with the exception of WerFault.exe during rare system crash scenarios. Security researchers and incident responders have identified that the spawning of arbitrary child processes by consent.exe is a reliable indicator of UAC bypass exploits and privilege escalation. Attackers utilize these techniques to achieve elevated privileges without triggering a visible user prompt, effectively bypassing standard Windows security boundaries. This behavior is frequently associated with post-exploitation frameworks targeting Windows environments, particularly in the context of CVE-2024-30051. Detection of this activity is critical for identifying local privilege escalation attempts where attackers attempt to maintain stealth during the elevation phase.

## Impact

Successful exploitation of UAC bypass techniques allows unauthorized users to gain elevated system privileges. This provides an attacker with the ability to execute malicious payloads with administrative rights, potentially leading to full system compromise, exfiltration of sensitive data, or the deployment of secondary malware. These techniques are often utilized during the post-exploitation phase to gain persistence and deeper access within target networks.

## Recommendation

* Enable Sysmon Event ID 1 (Process Creation) or Windows Event ID 4688 to capture parent-child process relationships.
* Deploy the provided Sigma rule to identify and alert on non-WerFault.exe processes spawned by consent.exe.
* Investigate all alerts originating from consent.exe immediately, as legitimate software rarely triggers this behavior.
* Cross-reference identified processes with known administrative tools to rule out authorized maintenance activity.
