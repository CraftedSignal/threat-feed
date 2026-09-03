---
title: Abuse of PrintBrm.exe for File Operations
slug: 2026-09-printbrm-lolbin
description: PrintBrm.exe is a Living-off-the-Land Binary (LOLBIN) that can be abused by threat actors to perform unauthorized ZIP file creation or extraction on Windows systems.
date: "2026-09-03T13:46:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - lolbin
  - persistence
  - exfiltration
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: PrintBrm.exe can be used to create or extract ZIP files, facilitating tool transfer or exfiltration.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1564.004
    technique_name: 'Hide Artifacts: Unexpected File Extension'
    evidence: Using built-in binaries like PrintBrm.exe to manipulate ZIP files allows for the concealment of staged data.
    confidence_band: high
references:
  - https://lolbas-project.github.io/lolbas/Binaries/PrintBrm/
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_lolbin_printbrm.yml
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma detection rule for PrintBrm.exe activity.
      owner: Detection Engineering
      due: 48h
      evidence: Rule defined in brief
  hunt_leads:
    - lead: Search for historical process creation events involving PrintBrm.exe.
      technique_id: T1564.004
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Potential indicator of post-exploitation archive manipulation.
  mitigation_plan:
    - priority: medium_term
      action: Restrict PrintBrm.exe execution to authorized administrative accounts only.
      owner: IT Operations
      addresses: LOLBIN abuse
      evidence: Binary is rarely required on end-user workstations
---

PrintBrm.exe (PrintBrm.exe) is a legitimate Windows utility intended for printer migration and backup tasks. It has been identified as a Living-off-the-Land Binary (LOLBIN) that can be leveraged by attackers to manipulate archives. By utilizing specific command-line arguments, an adversary can use the binary to create or extract ZIP files, effectively masking malicious file staging or data exfiltration under the guise of a system process. Because this binary is rarely required on standard workstations, its execution is often indicative of post-exploitation activity, such as preparing data for exfiltration or unpacking secondary payloads. Defenders should treat the invocation of PrintBrm.exe with command-line flags involving file archives as suspicious.

## Attack Chain

1. Attacker gains initial access to a compromised Windows host.
2. Attacker identifies the target data to be exfiltrated.
3. Attacker discovers PrintBrm.exe on the target system.
4. Attacker executes PrintBrm.exe with the -f argument to target a specific file path.
5. Attacker provides a .zip extension to the file path to trigger archive creation.
6. PrintBrm.exe processes the files, creating an archive containing sensitive data.
7. Attacker uses a separate C2 channel to exfiltrate the generated archive.

## Impact

The abuse of PrintBrm.exe enables stealthy data staging and manipulation. If successful, an attacker can bypass standard security controls that monitor for common compression utilities (like 7zip or WinRAR) by leveraging a signed system binary to perform the same objective, leading to unauthorized data access and potential exfiltration.

## Recommendation

* Deploy the provided Sigma rule to detect suspicious PrintBrm.exe usage.
* Baseline the use of PrintBrm.exe across the environment; disable or restrict execution of this binary on endpoints where printer migration is not a required administrative task.
* Monitor for unexpected process-creation events involving PrintBrm.exe with command-line arguments containing file paths and ZIP extensions.

## Rules

- title: "Detect Suspicious PrintBrm.exe Usage"
 description: "Detects the execution of the LOLBIN PrintBrm.exe with arguments indicating the creation or extraction of ZIP files."
 logsource:
 category: "process_creation"
 product: "windows"
 detection:
 selection:
 Image|endswith: "\\PrintBrm.exe"
 CommandLine|contains|all:
 - "-f"
 - ".zip"
 condition: "selection"
 level: "high"
 tags:
 - "attack.command_and_control"
 - "attack.stealth"
 - "attack.t1105"
 - "attack.t1564.004"
 tests:
 positive:
 - name: "PrintBrm used to create a ZIP file"
 data:
 - Image: "C:\\Windows\\System32\\PrintBrm.exe"
 CommandLine: "PrintBrm.exe -f C:\\Temp\\data.zip"
 negative:
 - name: "Legitimate printer migration command"
 data:
 - Image: "C:\\Windows\\System32\\PrintBrm.exe"
 CommandLine: "PrintBrm.exe -b -f C:\\PrinterBackup"
 falsepositives:
 - "Legitimate administrative printer migration scripts that interact with ZIP-formatted archives."
 handoff:
 detection_confidence: "high"
 required_telemetry:
 - log_source: "Sysmon process_creation"
 event_or_channel: "Event ID 1"
 required_fields:
 - "Image"
 - "CommandLine"
 availability: "available"
 validation:
 status: "test_defined"
 steps:
 - "Run 'PrintBrm.exe -f C:\\test.zip' in a controlled lab environment."
 expected_telemetry: "Process creation event for PrintBrm.exe with the specified CLI."
 pass_criteria: "Detection rule triggers on the command line arguments."
 suggested_owner: "Detection Engineering"
