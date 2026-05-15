---
title: Gremlin Stealer Evolves with Advanced Obfuscation and Session Hijacking
slug: 2026-05-gremlin-stealer-evolution
description: The Gremlin stealer malware has evolved with advanced obfuscation techniques, crypto clipping, and session hijacking capabilities to steal sensitive information from compromised systems.
date: "2026-05-15T10:02:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - infostealer
  - credential-theft
  - session-hijacking
  - crypto-clipping
  - dotnet
vendors:
  - Palo Alto Networks
products:
  - Advanced WildFire
  - Advanced Threat Prevention
  - Advanced URL Filtering
  - Advanced DNS Security
  - Cortex XDR
  - Cortex XSIAM
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
references:
  - https://unit42.paloaltonetworks.com/gremlin-stealer-evolution/
iocs:
  - type: hash_sha256
    value: 2172dae9a5a695e00e0e4609e7db0207d8566d225f7e815fada246ae995c0f9b
ioc_counts:
  hash_sha256: 1
rules:
  - title: Detect Gremlin Stealer String Decoding Routine
    description: Detects Gremlin stealer's custom string decoding routine, which reads encrypted strings from an embedded resource file, indicating a potential unpacking stage.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: Detect Gremlin Stealer Data Exfiltration via Public IP Filename
    description: Detects Gremlin stealer exfiltrating data to a C2 server after naming the zip file with the victim's IP address.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

The Gremlin stealer malware has undergone significant evolution, incorporating advanced obfuscation and anti-analysis techniques. The latest variant conceals malicious payloads within embedded resources, employing XOR encoding and a complex commercial packing utility to evade detection. This version targets web browsers, system clipboards, and local storage to exfiltrate sensitive information such as payment card details, browser cookies, session tokens, cryptocurrency wallet data, FTP, and VPN credentials. A notable feature is the WebSocket-based session hijacking module that allows the malware to bypass modern cookie protections by directly requesting data from the running browser process. The malware also includes a crypto clipper functionality, which monitors the system clipboard for cryptocurrency wallet patterns and replaces the victim's address with the attacker’s wallet in real time.

## Attack Chain

1.  The attacker deploys a Gremlin stealer variant packed with a commercial packing utility.
2.  The malware loads the main payload from a .NET resource section, which is XOR encoded to evade signature-based detection.
3.  The malware decrypts strings at runtime using a custom decoder ring function `_003CModule_003E.c(int, int, int)` which reads encrypted strings from an embedded resource file.
4.  The stealer targets web browsers to steal payment card details, browser cookies, and session tokens using a class, BrowserCredentialStealer.
5.  It monitors the system clipboard for cryptocurrency wallet addresses and replaces the victim's address with the attacker's address in real time.
6.  The malware uses a WebSocket-based session hijacking module to steal session data from running browser processes.
7.  The stealer exfiltrates the stolen data, bundled into a ZIP archive named using the victim's public IP address, to the C2 server at hxxp[:]194.87.92[.]109/i.php.
8.  The C2 server receives and stores the stolen data, potentially for sale or publication.

## Impact

Successful Gremlin stealer infections can lead to significant financial losses due to the theft of payment card details and cryptocurrency wallet data. Stolen session tokens and credentials can provide attackers with unauthorized access to sensitive accounts, potentially leading to further compromise and data breaches. The exfiltration of FTP and VPN credentials can allow attackers to pivot to other systems within the victim's network. This malware represents a significant threat to individuals and organizations alike, potentially impacting thousands of users.

## Recommendation

*   Block the C2 IP address `194.87.92[.]109` at the firewall or DNS resolver to prevent data exfiltration.
*   Implement endpoint detection and response (EDR) solutions capable of detecting and blocking the execution of packed .NET executables similar to the one with SHA256 hash `2172dae9a5a695e00e0e4609e7db0207d8566d225f7e815fada246ae995c0f9b`.
*   Deploy the Sigma rule "Detect Gremlin Stealer String Decoding Routine" to identify the malware's string decryption function.
*   Enable Sysmon process creation logging to improve visibility into process execution and identify suspicious parent-child process relationships associated with the stealer.
