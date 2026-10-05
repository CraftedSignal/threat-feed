---
title: Detection of Native .NET Binaries Executing from Non-Standard Paths
slug: 2026-10-windows-dotnet-non-standard
description: Adversaries move native Windows .NET binaries to unconventional directories to bypass security controls and facilitate malicious code execution or persistence.
date: "2026-10-05T12:22:08Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - masquerading
  - windows
  - endpoint-security
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Adversaries may move .NET binaries to unconventional paths to evade detection.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: This activity is significant because adversaries may move .NET binaries to unconventional paths... specifically linked to ... proxy execution via InstallUtil.
    confidence_band: high
references:
  - https://attack.mitre.org/techniques/T1036/003/
  - https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/
rules:
  - title: Detect .NET Binary Execution from Non-Standard Paths
    description: Detects the execution of known native .NET binaries from directories outside of standard Windows system paths, which may indicate masquerading or evasion.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1036.003
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
    - action: Deploy the .NET non-standard path detection rule and tune against known benign third-party software in the environment.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides technical logic for identifying .NET binary masquerading.
  hunt_leads:
    - lead: Search for non-standard process paths involving common .NET binaries (e.g., InstallUtil.exe, csc.exe).
      technique_id: T1036.003
      data_needed:
        - Process creation logs with full path information.
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Analytic described in the source material.
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict application execution policies and utilize AppLocker or WDAC to restrict execution of binaries from user-writable directories.
      owner: IT Operations
      addresses: T1036.003
      evidence: Standard security practice for mitigating masquerading.
---

Adversaries frequently employ masquerading techniques to evade detection by moving legitimate native .NET binaries, such as InstallUtil or similar system utilities, to non-standard, unconventional directories on Windows systems. By executing these binaries from locations outside of trusted paths like C:\Windows\System32, C:\Windows\SysWOW64, or C:\Windows\WinSxS, attackers attempt to blend in with legitimate activity while establishing persistence, escalating privileges, or executing arbitrary malicious code. This technique is specifically linked to masquerading system utilities (T1036.003) and proxy execution (T1218.004) to hide execution flows from standard security monitoring. This behavior has been observed in various destructive malware campaigns, including operations like WhisperGate. Detecting these deviations requires monitoring EDR telemetry for process executions where the file name matches a known .NET binary but the path does not align with expected system structures.

## Impact

Successful execution of .NET binaries from non-standard locations allows attackers to bypass baseline security restrictions, potentially leading to unauthorized data destruction, system compromise, or long-term persistence in the target environment. This activity is often a precursor to more severe impacts, including ransomware deployment or the exfiltration of sensitive information.

## Recommendation

Prioritize the implementation of EDR-based detection logic to identify .NET binaries running from suspicious locations.
- Enable process creation monitoring (Sysmon Event ID 1 or Security Event 4688) to capture the required process path, process name, and original file name metadata.
- Deploy the provided Sigma rule to SIEM environments to alert on unauthorized execution paths for identified .NET binaries.
- Review and tune existing whitelist policies to ensure that third-party applications do not trigger false positives when executing legitimately from custom installation directories.
