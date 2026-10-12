---
title: Suspicious Mshta.exe Child Process Execution
slug: 2026-10-suspicious-mshta-child-process
description: This detection focuses on identifying suspicious child processes spawned from 'mshta.exe', a common living-off-the-land technique used by threat actors like Lumma Stealer and MuddyWater for code execution and persistence.
date: "2026-10-12T17:59:14Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - living-off-the-land
  - execution
  - defense-evasion
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: mshta.exe is often exploited by attackers to execute malicious scripts or commands.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/suspicious_mshta_child_process.yml
  - https://redcanary.com/blog/introducing-atomictestharnesses/
rules:
  - title: Detect Suspicious Mshta Child Processes
    description: Detects potentially malicious child processes spawned from mshta.exe, which is a common indicator of living-off-the-land exploitation.
    platform: sigma
    severity: medium
    tactics:
      - defense-evasion
      - execution
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to monitor mshta.exe process lineage.
      owner: Detection Engineering
      due: 24h
      evidence: Source analytic requires EDR telemetry for parent-child tracking.
  hunt_leads:
    - lead: Search for non-standard child processes of mshta.exe in historical process telemetry.
      technique_id: T1218.005
      data_needed:
        - Process creation events (PID, ParentPID, Commandline)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source highlights mshta.exe as a primary LOTL binary for spawning suspicious subprocesses.
  mitigation_plan:
    - priority: medium
      action: Implement application control policies to restrict unauthorized use of mshta.exe.
      owner: IT Operations
      addresses: T1218.005
      evidence: Technique T1218.005 relates to system binary proxy execution.
---

The 'mshta.exe' binary, a native Windows utility designed to execute Microsoft HTML Applications (HTA), is frequently leveraged by attackers to bypass security controls by executing malicious scripts directly from memory or remote locations. This threat activity involves 'mshta.exe' spawning child processes that are typically inconsistent with its legitimate purpose. 

Defenders should focus on monitoring for the execution of common living-off-the-land (LotL) binaries - including 'powershell.exe', 'cmd.exe', 'msbuild.exe', 'cscript.exe', and 'bitsadmin.exe' - when they are initiated with 'mshta.exe' as the parent process. This behavior is a recognized TTP used in campaigns by the MuddyWater threat group and during the delivery phases of infostealers such as Lumma Stealer. Monitoring these process relationships is essential for identifying early stages of compromise, including privilege escalation and the establishment of persistence.

## Attack Chain

1. The attacker delivers an HTA file to the target system via phishing or other initial access vectors.
2. The user or a malicious script triggers the execution of the HTA file, which invokes 'mshta.exe'.
3. 'mshta.exe' interprets the embedded malicious script (often VBScript or JScript).
4. The script within 'mshta.exe' executes system commands using 'cmd.exe' or 'powershell.exe' to download additional payloads or move laterally.
5. The attacker uses other binaries like 'msbuild.exe' or 'bitsadmin.exe' for secondary payload delivery or execution.
6. The spawned child processes perform malicious activity such as credential harvesting, exfiltration, or installing persistence mechanisms.

## Impact

Successful exploitation of this technique allows attackers to bypass application execution policies, execute arbitrary code, escalate privileges, and maintain long-term persistence. If unmonitored, this behavior facilitates the deployment of malware families such as infostealers, leading to the exfiltration of sensitive organizational data, compromised credentials, and potential ransomware deployment.

## Recommendation

1. Deploy the Sigma rules below to your SIEM/EDR environment to flag unauthorized 'mshta.exe' activity.
2. Ingest process creation telemetry (e.g., Sysmon Event ID 1 or Windows Event Log 4688) to capture the necessary 'ParentProcessName' and 'ProcessName' fields.
3. Tune the detection by creating allowlists for legitimate administrative or software-specific workflows that may utilize 'mshta.exe' legitimately.
4. Use the provided process-monitoring analytic to alert on high-risk child processes specifically including 'powershell.exe', 'cmd.exe', and 'msbuild.exe'.
