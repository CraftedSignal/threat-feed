---
title: GoSerpent Backdoor and Stowaway RAT Target Government Entities in Southeast Asia for Data Exfiltration
slug: 2026-07-goserpent-backdoor-southeast-asia
description: An unnamed threat actor is deploying a sophisticated two-phase attack, utilizing the GoSerpent backdoor, Stowaway RAT, and custom tools like ThumbcacheService and TmcLoader/TmcPayload, to persistently collect sensitive data and credentials from government and diplomatic entities in Southeast Asia for exfiltration.
date: "2026-07-16T12:11:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - backdoor
  - rat
  - data-exfiltration
  - government
  - southeast-asia
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: ThumbcacheService is a malicious DLL deployed as a Windows service... TmcLoader is a stealthy C++ loader module registered as a Windows service.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1543
    technique_name: Create or Modify System Process
    evidence: ThumbcacheService is a malicious DLL deployed as a Windows service... TmcLoader is a stealthy C++ loader module registered as a Windows service.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: The malware exhibits strong persistence mechanisms and uses filenames that mimic legitimate system processes such as lass.exe and updates.exe to evade detection.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: This malware receives encrypted and base64-encoded command-line arguments... TmcLoader employs dynamic API resolution through a circular XOR encryption where each byte is XORed with the value of the subsequent byte, combined with Base64 encoding for string obfuscation to hide API names.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
    evidence: 'The threat actor deploys the following tools via GoSerpent backdoor to dump credentials: Mimikatz — dumps memory from the LSASS process... QuarksDumpLocalHash — extracts local account password hashes from the SAM registry hive'
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: 'ThumbcacheService is a malicious DLL deployed as a Windows service that functions as a sophisticated file collection mechanism... It specifically targets documents with the following extensions: .doc, .docx, .pdf, .xls and .xlsx.'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: 'GoSerpent can establish SOCKS5 proxy servers... Stowaway features both network admin and agent capabilities enabling attackers to establish chained proxy paths across multiple hosts with the following functionalities: SOCKS5 proxying'
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: TmcPayload is responsible for exfiltrating sensitive data from the victim’s machine... exfiltrate sensitive data collected for the previous few months through network share.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
    evidence: ThumbcacheService is a malicious DLL deployed as a Windows service... TmcLoader is a stealthy C++ loader module registered as a Windows service.
    confidence_band: high
references:
  - https://securelist.com/goserpent-backdoor-in-southeast-asia/120687/
rules:
  - title: Detect GoSerpent Related Service Creation
    description: Detects the creation of Windows services related to the GoSerpent campaign, specifically ThumbcacheService and TmcLoader, used for data collection and exfiltration.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.003
    data_sources:
      - registry_set
      - windows
  - title: Detect GoSerpent Related Database File Creation
    description: Detects the creation of specific database files (thumbcache_605a.db, {BBF061R2-BE25-4F6D-8B2D-1A6A39C3FSA2}.db) used by the GoSerpent campaign for data collection and configuration.
    platform: sigma
    severity: high
    tactics:
      - collection
      - defense_evasion
    techniques:
      - T1005
      - T1027
    data_sources:
      - file_event
      - windows
  - title: Detect GoSerpent Credential Dumping Tools Execution
    description: Detects the execution of Mimikatz or QuarksDumpLocalHash, tools deployed by GoSerpent for credential access.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Since late 2025, an unnamed threat actor has been conducting a persistent, two-phase campaign targeting government and diplomatic organizations in Southeast Asia. The initial phase leverages the GoSerpent backdoor, a Go-based remote access Trojan first observed in 2021, which utilizes encrypted command-line arguments for C2 communication and masquerades as legitimate processes (`lass.exe`, `updates.exe`). GoSerpent is used to deploy additional tools, including a data collection utility named ThumbcacheService, and credential dumping tools like Mimikatz and QuarksDumpLocalHash. After several weeks of data and credential collection, a second phase begins, involving the deployment of the Stowaway RAT and the TmcLoader/TmcPayload module for stealthy, automated data exfiltration through network shares. This sophisticated operation demonstrates a high level of planning and technical capability focused on long-term data theft.

## Attack Chain

1. **Initial Deployment**: The GoSerpent backdoor, a Go-based remote access Trojan, is deployed on target systems. This variant receives encrypted and base64-encoded command-line arguments containing C2 server addresses and communication passwords.
2. **Persistence and Tool Delivery**: GoSerpent establishes persistence by using filenames that mimic legitimate system processes (e.g., `lass.exe`, `updates.exe`) and is then used to deploy secondary malicious tools.
3. **Data Collection Setup**: GoSerpent deploys `ThumbcacheService`, a malicious DLL registered as a Windows service. This service collects `.doc`, `.docx`, `.pdf`, `.xls`, and `.xlsx` files, archives them with 7-Zip using a specific password (`@vx0a9n5W2M0c3D6.#`), and stores them in `C:\Users\Public\thumbcache_605a.db`.
4. **Credential Dumping**: Concurrently, GoSerpent deploys credential dumping tools such as Mimikatz and QuarksDumpLocalHash to extract cached credentials from LSASS and local account password hashes from the SAM registry hive.
5. **Second Stage RAT Deployment**: After a period of data collection, the actor deploys `Stowaway`, another Go-based RAT and proxy tool, which supports SOCKS5 proxying, port forwarding, and remote shell access via TCP, HTTP, or WebSocket, encrypted with AES-256-GCM or TLS.
6. **Exfiltration Module Delivery**: `Stowaway` delivers `TmcLoader` (a C++ loader registered as a Windows service) and an encrypted configuration file `{BBF061R2-BE25-4F6D-8B2D-1A6A39C3FSA2}.db` to the victim machine.
7. **Payload Injection**: `TmcLoader` decrypts an embedded payload, `TmcPayload`, and injects it into the memory space of `svchost.exe` to maintain persistence and evade detection.
8. **Automated Data Exfiltration**: `TmcPayload` uses the previously collected credentials to access a network share and exfiltrate the sensitive archived data collected by `ThumbcacheService`.

## Impact

The impact of these attacks includes significant data breaches, specifically the theft of sensitive documents (Microsoft Office files, PDFs) and system credentials from government and diplomatic entities in Southeast Asia. This persistent threat model allows the actor to establish long-term access, continuously collect intelligence, and exfiltrate information over an extended period. Successful compromise could lead to espionage, loss of intellectual property, and compromise of critical government operations, potentially affecting national security and international relations for victim countries.

## Recommendation

* Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
* Enable Sysmon event logging for process creation (`Event ID 1`), file creation (`Event ID 11`), and registry modifications (`Event ID 12/13/14`) to activate the rules above.
* Monitor for the creation of `ThumbcacheService` and `TmcLoader` as new Windows services using the `Detect GoSerpent Related Service Creation` rule.
* Monitor for the creation of unique database files `thumbcache_605a.db` and `{BBF061R2-BE25-4F6D-8B2D-1A6A39C3FSA2}.db` in `C:\Users\Public\` and `C:\Users\Public\Libraries\` as detected by the `Detect GoSerpent Related Database File Creation` rule.
* Implement strong application whitelisting and monitor for the execution of known credential dumping tools like Mimikatz or QuarksDumpLocalHash, as detected by the `Detect GoSerpent Credential Dumping Tools Execution` rule.
