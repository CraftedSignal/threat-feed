---
title: DeadLock Ransomware Analysis
slug: 2026-08-deadlock-ransomware
description: DeadLock is an emerging Rust-based ransomware operation utilizing decentralized messaging and blockchain-backed infrastructure to support double extortion tactics and victim negotiations.
date: "2026-08-10T19:24:58Z"
type: advisory
types:
  - advisory
severities:
  - high
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.002
    technique_name: Bypass User Account Control
    evidence: The malware attempts to gain administrator privileges through a batch-script-based elevation technique.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1134
    technique_name: Access Token Manipulation
    evidence: When running with administrator privileges, the malware further expands its access by enabling SeDebugPrivilege, SeRestorePrivilege, SeBackupPrivilege, SeTakeOwnershipPrivilege, SeAuditPrivilege, and SeSecurityPrivilege.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
    evidence: The DeadLock encryptor includes a resource-aware throttling mechanism designed to maintain system responsiveness during encryption.
    confidence_band: high
references:
  - https://www.microsoft.com/en-us/security/blog/2026/08/10/deadlock-ransomware-breaking-down-a-rust-based-encryptor-with-decentralized-recovery-infrastructure/
---

DeadLock is a financially motivated ransomware operation that first emerged in July 2025. It is notable for its use of a decentralized recovery ecosystem, which integrates the Session messaging network with blockchain-backed services to manage victim communications, negotiations, and data leak hosting. This architecture is designed to improve the resilience of the operator's infrastructure against disruption. By July 2026, the group had claimed over 80 victims, primarily targeting sectors such as information technology, manufacturing, and logistics across Europe, Asia, Africa, and the Americas.

The DeadLock encryptor is written in Rust and includes a resource-aware throttling mechanism to ensure system stability during the encryption process. It implements specific geofencing logic, terminating execution if the system language matches a predefined list of CIS-linked and Middle Eastern countries. Operationally, the ransomware is deployed by multiple groups, including affiliates linked to the Lynx and INC ransomware ecosystems, emphasizing its role as a service-based operation.

## Attack Chain

1. Initial Execution: The ransomware is executed on a host, where it first performs a check against a hardcoded list of language IDs to geofence CIS-linked countries.
2. Privilege Elevation: The process attempts to gain administrator rights by generating a randomized .cmd file and executing it via ShellExecuteW with the 'RunAs' verb to trigger a UAC consent dialog.
3. Token Privilege Expansion: Once elevated, the encryptor enables multiple sensitive token privileges including SeDebugPrivilege, SeRestorePrivilege, and SeTakeOwnershipPrivilege to maximize file access.
4. Configuration Parsing: The malware decrypts an embedded configuration blob using XOR decoding with an 8-byte key to retrieve operational parameters and targets.
5. Environment Preparation: The process silently empties the Windows Recycle Bin on all mounted drives to prevent user-initiated data recovery.
6. Resource-Aware Encryption: The encryptor traverses the file system, excluding directories and extensions defined in its configuration, while employing throttling to maintain system responsiveness during file encryption.
7. Extortion: The malware deploys a ransom note and an HTML-based interactive chat recovery page, initiating the double-extortion phase where victims are threatened with public data release.

## Impact

DeadLock employs double-extortion tactics, combining full-environment encryption with the exfiltration and threat of public release of sensitive organizational data. With over 80 victims identified in one year, the operation significantly disrupts business operations across multiple global sectors. The use of decentralized infrastructure complicates law enforcement efforts to disrupt the negotiation and leak-hosting sites, potentially leading to prolonged incident response and recovery timelines for targeted entities.

## Recommendation

* Enable system-wide UAC logging and monitor for unusual .cmd file creation in temporary directories, which is a known technique for the DeadLock privilege escalation phase.
* Monitor for the creation of unauthorized files in the Windows Recycle Bin directory paths and investigate processes that invoke mass deletion/emptying of the bin without legitimate administrative context.
* Implement security policies to restrict the usage of sensitive token privileges (SeDebugPrivilege, SeTakeOwnershipPrivilege) for non-administrative accounts and monitor for their enablement by untrusted processes.
* Analyze outbound network traffic for connections to decentralized messaging networks like Session, which may indicate active ransomware negotiation or C2 activity in the environment.
