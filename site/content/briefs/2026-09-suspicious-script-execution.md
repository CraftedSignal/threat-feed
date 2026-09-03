---
title: Detection of Script Interpreter Execution from Suspicious Directories
slug: 2026-09-suspicious-script-execution
description: Adversaries frequently utilize script interpreters such as cscript, wscript, and mshta from non-standard or user-writable directories to execute malicious payloads while evading security controls.
date: "2026-09-03T12:45:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - living-off-the-land
  - detection-engineering
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Script interpreters (cscript, wscript, mshta, powershell) executing from folders like Temp, Public, or user profile directories may suggest attempts to evade detection.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_script_exec_from_env_folder.yml
  - https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/shuckworm-russia-ukraine-military
rules:
  - title: Detect Script Interpreter Execution From Suspicious Folder
    description: Detects execution of script interpreters from common user-writable or temporary directories often used by malware.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
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
    - action: Deploy Sigma rule to SIEM/EDR platform
      owner: Detection Engineering
      due: 48h
      evidence: Source provides high-fidelity logic for detecting script-based evasion
  hunt_leads:
    - lead: Search for script interpreters launching from %TEMP% or %PUBLIC% in the last 30 days
      technique_id: T1059
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This behavior is a high-indicator for post-exploitation staging
  mitigation_plan:
    - priority: medium_term
      action: Enforce strict execution policies via GPO
      owner: IT Operations
      addresses: T1059
      evidence: Execution policy enforcement limits arbitrary script execution
---

Adversaries often weaponize built-in Windows script interpreters to execute malicious code within a compromised environment. By placing scripts in directories like Temp, Public, or user-profile folders, attackers leverage locations where they have write permissions, minimizing the likelihood of triggering security alerts associated with system-wide changes. These techniques are often employed during the initial access or post-exploitation phases, using interpreters like cscript.exe, wscript.exe, and mshta.exe to carry out tasks such as code execution, persistence, or data staging. Defending against this requires monitoring for process creation events where these specific interpreters are invoked from anomalous paths, particularly when combined with execution policy bypass flags or hidden window parameters.

## Attack Chain

1. Attacker establishes initial access via phishing or vulnerability exploitation.
2. Attacker writes a malicious script or shellcode-based payload to a writable directory like %TEMP% or C:\Users\Public\.
3. Attacker stages a secondary script or executable in the same user-writable location.
4. Attacker invokes a legitimate script interpreter process (cscript, wscript, or mshta).
5. Interpreter process executes the staged script using command-line arguments to bypass execution policies or hide windows (e.g., -ep bypass).
6. Malicious code executes in the context of the user, leading to potential credential dumping or C2 beaconing.
7. Final objective achieved, such as long-term persistence or data exfiltration.

## Impact

Successful exploitation of this technique allows attackers to execute arbitrary code with the permissions of the compromised user account. This often serves as a precursor to lateral movement, data theft, or the deployment of ransomware. Victims in sectors such as military, government, and critical infrastructure have been observed targeted by sophisticated groups leveraging these living-off-the-land techniques.

## Recommendation

Deploy the provided Sigma rule to identify script execution from known user-writable or temporary directories and tune against baseline environment noise.

- Enable Sysmon or Windows Security event logging (Event ID 4688) to capture process creation telemetry.
- Review and baseline legitimate administrative or installation scripts that trigger this behavior to create robust filter sets for the Sigma rule.
- Monitor for unauthorized files created in \Users\Public\ and \AppData\Local\Temp\ directories.
