---
title: Credential Acquisition via Registry Hive Dumping
slug: 2024-01-registry-hive-dump
description: Attackers may dump the SECURITY and/or SAM hives to obtain credentials stored in the host by using the Windows reg.exe tool.
date: "2024-01-02T18:11:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - credential-access
  - registry-dump
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
references:
  - https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-the-registry-7512674487f8
  - https://www.elastic.co/security-labs/detect-credential-access
rules:
  - title: Registry Hive Dumping with Reg.exe
    description: Detects the execution of reg.exe to save or export the SAM or SECURITY registry hives, indicating potential credential theft.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1003.002
      - T1003.004
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Reg.exe Process Tree
    description: Detects reg.exe execution with potential registry hive dumping as a child of uncommon parent processes.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1003.002
      - T1003.004
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers commonly dump registry hives to access credential information stored within them. The SAM hive stores locally cached credentials (SAM Secrets), while the SECURITY hive stores domain cached credentials (LSA secrets). Combining these hives with the SYSTEM hive allows decryption of the secrets. This activity is frequently observed in post-exploitation scenarios where the attacker aims to escalate privileges or move laterally within a network. This brief focuses on detecting the use of `reg.exe` to dump the SECURITY and/or SAM hives, indicating a potential compromise of credentials stored on the host. The detection logic is based on process execution events involving `reg.exe` with specific arguments used for saving or exporting targeted registry hives.

## Attack Chain

1. An attacker gains initial access to a Windows system, potentially through phishing or exploiting a vulnerability.
2. The attacker executes `reg.exe` to dump the SAM or SECURITY registry hives.
3. The `reg.exe` command uses the `save` or `export` argument to copy the hive to a file.
4. The attacker specifies the target hive, either `hklm\sam` or `hklm\security`, as an argument to `reg.exe`.
5. The dumped registry hive is saved to a file on the system.
6. The attacker retrieves the SYSTEM hive to facilitate credential decryption.
7. The attacker uses tools to extract credentials from the dumped SAM and SECURITY hives using the SYSTEM hive for decryption.
8. The attacker uses the acquired credentials for lateral movement, privilege escalation, or data exfiltration.

## Impact

Successful exploitation can lead to the compromise of sensitive credentials stored on the targeted system, enabling attackers to move laterally within the network, escalate privileges, and potentially gain access to critical data and systems. The compromise can affect the entire domain if domain cached credentials are stolen. The severity depends on the access level of the compromised account and the sensitivity of the data accessible through that account.

## Recommendation

*   Enable process creation logging and monitor for command-line arguments to detect the execution of `reg.exe` with the `save` or `export` arguments targeting `hklm\sam` or `hklm\security` (see Sigma rule `Registry Hive Dumping with Reg.exe`).
*   Implement detections for the use of credential dumping tools and techniques, as outlined in the MITRE ATT&CK techniques T1003.002 (Security Account Manager) and T1003.004 (LSA Secrets).
*   Review and harden registry permissions to restrict access to sensitive registry hives like SAM and SECURITY, mitigating the risk of unauthorized dumping.
*   Investigate any alerts related to registry hive dumping promptly to determine the scope and impact of the potential credential compromise, following the investigation steps outlined in the rule's description.
