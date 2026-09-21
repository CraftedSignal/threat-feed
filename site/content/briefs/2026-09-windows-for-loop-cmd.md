---
title: Detection of Suspicious Command-Line For Loop Parsing
slug: 2026-09-windows-for-loop-cmd
description: Adversaries leverage 'for /f' loops within 'cmd.exe' to programmatically extract and process data from system command outputs for discovery and post-exploitation tasks.
date: "2026-09-21T13:07:57Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - lotl
  - detection
  - cmd
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The following analytic identifies the use of a for /f loop with the delims= option within cmd.exe, a technique commonly used to parse and extract data.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_for_loop_usage_within_cmd_exe_to_execute_commands.yml
  - https://packetwatch.com/resources/threat-profile/clickfix-abuses-finger-to-deliver-castleloader
rules:
  - title: Detect Suspicious For Loop Usage in Cmd.exe
    description: Detects the use of 'for /f' loops with 'delims=' in cmd.exe, a common technique for command output parsing by attackers.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to EDR or SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source detection documentation
  hunt_leads:
    - lead: Search for instances of cmd.exe /c for /f in telemetry from the last 30 days
      technique_id: T1059.003
      data_needed:
        - Process creation logs
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Technique commonly used by adversaries for discovery
---

Adversaries and malicious scripts commonly utilize the Windows command-line interpreter 'cmd.exe' to execute 'for /f' loops with the 'delims=' delimiter option. This specific syntax allows attackers to parse, filter, and extract targeted data from the output of built-in system utilities, facilitating reconnaissance and data staging during post-exploitation activities. This technique is a subset of Living-off-the-Land (LotL) behaviors, enabling attackers to remain stealthy by avoiding the introduction of non-native binaries. Defenders should focus on identifying instances of this command pattern where the execution context originates from non-SYSTEM accounts or unexpected parent processes, as legitimate administrative automation typically follows predictable patterns.

## Attack Chain

1. Initial access is established through phishing, exploitation, or credential compromise.
2. The adversary initiates a cmd.exe process to run enumeration commands (e.g., net, ipconfig, tasklist).
3. The output of these commands is piped or captured into a variable or temporary file.
4. The adversary executes 'cmd.exe /c for /f "delims=..."' to parse the previously captured data.
5. Specific strings, credentials, or system identifiers are extracted from the command output based on the provided delimiter.
6. The extracted data is used to inform further discovery or the next stage of the attack.
7. The final objective is typically information gathering, credential theft, or the preparation for secondary payload execution.

## Impact

Successful execution of this technique facilitates refined data exfiltration, automated discovery, and the extraction of sensitive system information. It is commonly observed in post-exploitation scenarios, including credential harvesting campaigns and malware loaders such as Castleloader, where it is used to process environment data.

## Recommendation

1. Enable Sysmon Event ID 1 (Process Creation) to capture detailed command-line arguments across the environment.
2. Deploy the provided Sigma detection rule to identify 'for /f' loop execution patterns.
3. Tune the detection by adding legitimate administrative and software deployment paths to the filter block.
4. Investigate alerts originating from non-SYSTEM service accounts or user-initiated cmd.exe sessions.
