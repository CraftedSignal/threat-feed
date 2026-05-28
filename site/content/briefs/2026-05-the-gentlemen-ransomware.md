---
title: 'The Gentlemen Ransomware: Self-Propagating Go Encryptor'
slug: 2026-05-the-gentlemen-ransomware
description: The Gentlemen ransomware, operated by Storm-2697 as a RaaS, employs a combination of strong per-file encryption with aggressive self-propagation to achieve broad network compromise, targeting Windows environments and using double extortion tactics.
date: "2026-05-28T15:40:43Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - Storm-2697
tags:
  - ransomware
  - raas
  - lateral-movement
  - encryption
vendors:
  - Microsoft
products:
  - Microsoft Defender
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://www.microsoft.com/en-us/security/blog/2026/05/28/the-gentlemen-ransomware-dissecting-a-self-propagating-go-encryptor/
rules:
  - title: Detect The Gentlemen Ransomware Execution with Full Argument
    description: Detects execution of The Gentlemen ransomware with the '--full' argument, indicating a comprehensive encryption attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1204.002
      - T1486
    data_sources:
      - process_creation
      - windows
  - title: Detect The Gentlemen Ransomware Spawned System Process
    description: Detects execution of The Gentlemen ransomware spawned with the '--system' argument, which encrypts local volumes under a SYSTEM-privileged scheduled task.
    platform: sigma
    severity: high
    tactics:
      - execution
      - impact
    techniques:
      - T1204.002
      - T1486
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

The Gentlemen ransomware is a ransomware-as-a-service (RaaS) operated by the financially motivated threat actor Storm-2697, which emerged around mid-2025 and began offering its RaaS to affiliates in September 2025. This ransomware is written in Go and obfuscated with Garble, targeting Windows environments. The operators behind the ransomware use double extortion tactics, encrypting data while also exfiltrating sensitive information. The Gentlemen ransomware combines strong per-file encryption with an aggressive self-propagation capability, using a series of simultaneous lateral movement methods to spread across an environment after initial access is achieved. Microsoft has observed this ransomware impacting organizations across education, transportation, healthcare, and financial industries globally. More recently, The Gentlemen operators have partnered with BreachForums to recruit affiliates.

## Attack Chain

1.  Initial access is gained through unspecified means, potentially leveraging initial access brokers recruited via BreachForums.
2.  The Gentlemen ransomware is executed on the target system, requiring a password via the `--password` command-line argument.
3.  The ransomware parses command-line arguments to determine encryption scope, speed, and lateral movement options.
4.  If the `--full` argument is provided, the malware spawns two child processes: one with `--system` to encrypt local drives under SYSTEM privileges, and another with `--shares` to encrypt network shares.
5.  The ransomware uses per-file ephemeral Curve25519 keys with XChaCha20 stream cipher to encrypt files. The speed of encryption is determined by arguments like `--fast`, `--superfast`, or `--ultrafast`.
6.  For lateral movement, the `--spread` argument is used to propagate to other systems, accepting credentials or using the current session token.
7.  After encryption, the ransomware may delete itself unless the `--keep` argument is provided. It may also wipe free disk space if the `--wipe` argument is used.
8.  Victims are presented with a ransom note, and sensitive data is exfiltrated to pressure victims to pay the ransom.

## Impact

The Gentlemen ransomware has impacted organizations across various industries including education, transportation, healthcare, and financial services in North America, South America, Europe, Africa, and Asia. A successful attack results in data encryption, exfiltration of sensitive information, and significant operational disruption. Victims are pressured to pay a ransom to regain access to their data and prevent the public release of stolen information.

## Recommendation

*   Monitor process creation events for execution of binaries with command-line arguments specifying encryption scope, speed, and lateral movement options, especially the `--full`, `--system`, and `--shares` arguments (see Sigma rule "Detect The Gentlemen Ransomware Execution with Full Argument").
*   Enable Microsoft Defender and review detections related to The Gentlemen ransomware. Use the provided hunting queries to proactively search for related activity in your environment.
*   Implement strict password policies and multi-factor authentication to reduce the risk of credential compromise and lateral movement.
*   Regularly back up critical data to an offsite location to ensure recoverability in the event of a ransomware attack.
