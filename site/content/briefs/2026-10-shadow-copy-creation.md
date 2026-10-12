---
title: Detection of Unauthorized Shadow Copy Creation
slug: 2026-10-shadow-copy-creation
description: The unauthorized creation of volume shadow copies using system utilities is a common technique used by attackers to bypass file locks and facilitate credential dumping from protected registry hives.
date: "2026-10-12T17:38:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.003
    technique_name: 'OS Credential Dumping: NTDS'
    evidence: The creation of volume shadow copies via utilities such as vssadmin.exe or wmic.exe is a common technique used by attackers to bypass file locks and gain access to sensitive files, including the SAM and SYSTEM registry hives for offline credential dumping.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1003.003
    technique_name: 'OS Credential Dumping: NTDS'
    evidence: The analytic detects the creation of shadow copies... significant because creating shadow copies can be a precursor to ransomware attacks or data exfiltration.
    confidence_band: high
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma detection rule to SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in brief
  hunt_leads:
    - lead: Search for past execution of vssadmin.exe or wmic.exe with shadow copy creation arguments
      technique_id: T1003.003
      data_needed:
        - Endpoint process execution logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source document indicates this is a common attacker TTP
---

Attackers frequently abuse built-in Windows utilities such as vssadmin.exe and wmic.exe to create volume shadow copies. This technique allows adversaries to bypass file system locks that typically prevent direct access to sensitive system files, including the SAM and SYSTEM registry hives. By generating a shadow copy, attackers can then extract these hives to perform offline credential dumping. This activity is a high-fidelity signal often observed as a precursor to broader intrusion objectives, including lateral movement, data exfiltration, or the deployment of ransomware. Monitoring for the execution of these utilities with specific command-line arguments is critical for identifying early-stage reconnaissance and credential access attempts in Windows environments.

## Attack Chain

1. Initial access is established on the Windows host via spearphishing or exploited vulnerability.
2. The attacker executes a command to create a volume shadow copy using 'vssadmin.exe create shadow /for=C:' or 'wmic.exe shadowcopy call create'.
3. The system creates a persistent snapshot of the volume, bypassing locked-file restrictions.
4. The attacker accesses the volume snapshot path to locate the SYSTEM and SAM registry hives.
5. Registry hives are exfiltrated or copied to a staging directory using standard file utilities.
6. The sensitive registry files are moved off the endpoint to an attacker-controlled infrastructure.
7. Offline brute-forcing of the extracted NTLM hashes or LSA secrets is performed to gain plaintext credentials.
8. The attacker leverages compromised administrative credentials to achieve further lateral movement or ransomware deployment.

## Impact

Successful exploitation allows an attacker to gain unauthorized access to administrative or domain credentials by bypassing standard Windows file protections. This typically results in full credential compromise, enabling lateral movement within the environment, persistent access, and potential large-scale data encryption or exfiltration.

## Recommendation

Prioritize the identification of shadow copy creation events by integrating EDR process telemetry into the SIEM. Deploy the Sigma rules below to alert on the use of vssadmin.exe or wmic.exe with parameters associated with shadow copy management. Establish a baseline for administrative behavior to minimize false positives, as IT operations may perform these actions for legitimate backup or recovery tasks.

## Sigma Rules
- title: "Detect Shadow Copy Creation via Vssadmin or Wmic"
 description: "Detects the creation of shadow copies using Vssadmin or Wmic, a technique often used for offline credential dumping."
 logsource:
 category: "process_creation"
 product: "windows"
 detection:
 selection_vss:
 Image|endswith: "\\vssadmin.exe"
 CommandLine|contains:
 - "create"
 - "shadow"
 selection_wmic:
 Image|endswith: "\\wmic.exe"
 CommandLine|contains:
 - "shadowcopy"
 - "create"
 condition: selection_vss or selection_wmic
 level: "medium"
 tags:
 - "attack.credential_access"
 - "attack.t1003.003"
 tests:
 positive:
 - name: "Shadow copy creation via vssadmin"
 data:
 - Image: "C:\\Windows\\System32\\vssadmin.exe"
 CommandLine: "vssadmin.exe create shadow /for=C:"
 - name: "Shadow copy creation via wmic"
 data:
 - Image: "C:\\Windows\\System32\\wbem\\wmic.exe"
 CommandLine: "wmic shadowcopy call create"
 negative:
 - name: "Benign usage of vssadmin"
 data:
 - Image: "C:\\Windows\\System32\\vssadmin.exe"
 CommandLine: "vssadmin list shadows"
 falsepositives:
 - "Legitimate administrative activity for backup or system recovery"
 handoff:
 detection_confidence: "high"
 required_telemetry:
 - log_source: "Sysmon process_creation"
 event_or_channel: "Event ID 1"
 required_fields:
 - "Image"
 - "CommandLine"
 availability: "available"
 notes: "Requires command line logging to be enabled."
 validation:
 status: "needs_environment_validation"
 steps:
 - "Execute 'vssadmin create shadow /for=C:' in a controlled lab environment"
 expected_telemetry: "Process creation event matching vssadmin and the shadow creation arguments"
 pass_criteria: "Detection rule triggers"
 atomic_reference: "T1003.003"
 limitations:
 - "Will not catch shadow copies created via native API calls directly from C++ code or specialized tools not using these binaries"
 suggested_owner: "Detection Engineering"
