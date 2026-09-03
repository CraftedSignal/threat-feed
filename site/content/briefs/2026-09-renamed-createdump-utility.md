---
title: Detection of Renamed CreateDump Utility Execution
slug: 2026-09-renamed-createdump-utility
description: Adversaries may rename the legitimate createdump.exe utility to evade detection while performing unauthorized process memory dumps for credential access.
date: "2026-09-03T12:42:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - stealth
  - living-off-the-land
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Adversaries may rename the legitimate createdump.exe utility to evade detection.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003.001
    technique_name: LSASS Memory
    evidence: The utility is used to dump process memory, commonly for credential access purposes.
    confidence_band: high
references:
  - https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/
  - https://twitter.com/bopin2020/status/1366400799199272960
rules:
  - title: Detect Renamed CreateDump Utility Execution
    description: Detects the execution of the legitimate createdump.exe utility that has been renamed, using the original filename metadata.
    platform: sigma
    severity: high
    tactics:
      - credential-access
      - stealth
    techniques:
      - T1003.001
      - T1036
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
    - action: Deploy detection rule for renamed createdump.exe
      owner: Detection Engineering
      due: 48h
      evidence: Rule provided in brief
  hunt_leads:
    - lead: Search for instances of process creation where OriginalFileName is 'createdump.exe' but the Image path does not end in 'createdump.exe'
      technique_id: T1036
      data_needed:
        - Process creation events
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: Source rule logic
---

The built-in Windows utility 'createdump.exe' is a legitimate tool used for generating process dumps. Threat actors and penetration testers frequently abuse this utility to extract sensitive information, such as passwords or cryptographic keys, from the memory of high-value processes like 'lsass.exe'. To bypass basic file-path-based security controls or allowlists, attackers often copy 'createdump.exe' to a different location and rename the binary before execution. By monitoring for the execution of binaries that maintain the internal metadata of 'createdump.exe' but carry a non-standard filename, defenders can identify attempts to mask malicious memory dumping activities. This technique is a form of LOLOBIN (Living Off the Land Binary) exploitation used to facilitate credential access.

## Attack Chain

1. Attacker gains initial access or code execution on the target Windows system.
2. Attacker locates the legitimate 'createdump.exe' binary on the filesystem.
3. Attacker copies the 'createdump.exe' file to a temporary or staging directory (e.g., C:\ProgramData\).
4. Attacker renames the copied binary to a deceptive or benign-looking filename.
5. Attacker executes the renamed binary with arguments designed to dump target process memory (e.g., -u or --full for full memory dump).
6. The utility writes a memory dump file (e.g., .dmp) to the local disk.
7. Attacker exfiltrates the generated memory dump file to an external C2 server for offline processing.
8. Attacker uses tools like Mimikatz or a debugger to extract credentials from the collected dump.

## Impact

Successful execution of this technique allows unauthorized actors to harvest plaintext credentials, Kerberos tickets, and other secrets from system memory. This enables lateral movement, privilege escalation, and persistent access within the compromised environment. While the impact is typically restricted to the scope of the individual host, the stolen credentials often provide the means to compromise the entire domain or cloud identity provider.

## Recommendation

1. Deploy the Sigma rule provided in this brief to detect the execution of renamed 'createdump.exe' binaries.
2. Enable process-creation logging (e.g., Sysmon Event ID 1) to capture the 'OriginalFileName' attribute, which is necessary for detecting the renamed binary.
3. Configure security software to flag or block the execution of 'createdump.exe' from non-standard locations if the utility is not required for legitimate administrative or debugging tasks.
4. Investigate any file system alerts related to the creation of .dmp files in unauthorized directories.
