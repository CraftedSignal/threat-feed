---
title: Detection of Hashcat Password Cracker Execution
slug: 2026-09-hashcat-execution
description: Detection engineering brief regarding the use of the Hashcat password recovery tool in Windows environments, which is frequently used by adversaries for credential access via offline hash cracking.
date: "2026-09-01T11:06:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - tool
  - windows
  - security-tooling
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: Hashcat is a password recovery tool used for credential access via offline hash cracking.
    confidence_band: high
rules:
  - title: Detect Hashcat Password Cracker Execution
    description: Detects execution of hashcat.exe potentially used for offline password cracking via common command line arguments
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.002
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
    - action: Deploy Sigma rule for Hashcat detection
      owner: Detection Engineering
      due: 48h
      evidence: Source provides detection logic for Hashcat
  hunt_leads:
    - lead: Search for hashcat.exe execution in process logs
      technique_id: T1110.002
      data_needed:
        - Process creation events (Event ID 1)
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Hashcat is a common tool for offline password cracking.
---

Hashcat is a widely used advanced password recovery tool that supports various hashing algorithms. In offensive operations, adversaries utilize Hashcat to crack password hashes extracted from compromised systems, such as SAM database exports or NTDS.dit files. Defenders must monitor for the execution of hashcat.exe, particularly when used in conjunction with command-line arguments specifying attack modes (-a), hash types (-m), or rule-based cracking files (-r). While legitimate security assessments and authorized penetration tests employ this tool, its presence on endpoints often signals active credential access or post-exploitation activity where an attacker has already successfully bypassed system-level protections to obtain credentials.

## Impact

Successful execution of Hashcat by unauthorized actors leads to the recovery of plaintext passwords, facilitating lateral movement, privilege escalation, and persistent access to the organization's network.

## Recommendation

- Deploy the provided Sigma rule to detect unauthorized Hashcat process creation events.
- Investigate any detected execution of hashcat.exe to determine if it aligns with authorized penetration testing or security assessment activity.
- Proactively secure sensitive credential stores such as the SAM registry hive and NTDS.dit file by implementing strict access control lists and monitoring for unauthorized file access.
