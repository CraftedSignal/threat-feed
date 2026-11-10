---
brief_id: brief-2026-11-10-msiexec-masquerading
event_id: brief-2026-11-10-msiexec-masquerading
revision: 1
activity_at: "2026-11-10T06:43:23Z"
title: Potential MsiExec Masquerading
slug: 2026-11-msiexec-masquerading
description: Detection of msiexec.exe execution from unauthorized directories, a technique used by adversaries to masquerade as legitimate Windows Installer processes.
date: "2026-11-10T06:43:23Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment testing
tags:
  - stealth
  - process-masquerading
  - windows
  - defensive-evasion
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    subtechnique_id: T1036.005
    subtechnique_name: Match Legitimate Name or Location
    evidence: Detects the execution of msiexec.exe from an uncommon directory
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_msiexec_masquerading.yml
  - https://web.archive.org/web/20191114000442/https://twitter.com/200_okay_/status/1194765831911215104
rules:
  - title: Detect Potential MsiExec Masquerading
    description: Detects the execution of msiexec.exe from directories outside of standard Windows system paths.
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1036.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to production SIEM
      owner: Detection Engineering
      due: 48h
      evidence: High confidence detection rule for common masquerading technique
  hunt_leads:
    - lead: Search for all instances of msiexec.exe not located in C:\Windows\System32, C:\Windows\SysWOW64, or C:\Windows\WinSxS
      technique_id: T1036.005
      data_needed:
        - Process execution telemetry including full path
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Direct observation of masquerading potential
  mitigation_plan:
    - priority: medium
      action: Apply execution policies or AppLocker/WDAC rules to restrict non-authorized executable paths
      owner: IT Operations
      addresses: Masquerading techniques
      evidence: General best practice for binary masquerading prevention
---

Adversaries often attempt to masquerade malicious executables as legitimate Windows system binaries. One such technique involves executing a file named 'msiexec.exe' from a directory other than the standard Windows system folders. This practice attempts to evade detection by hiding within the expected activity of the Windows Installer service.

## Recommendation
- Deploy the Sigma rule provided in this brief to your SIEM to monitor for 'msiexec.exe' processes originating from non-standard file paths.
- Review and baseline existing legitimate software installation processes that may use custom installers or unconventional deployment paths to avoid false positives.
- Ensure Sysmon Event ID 1 (Process Creation) is enabled, specifically capturing the 'Image' and 'OriginalFileName' fields.
