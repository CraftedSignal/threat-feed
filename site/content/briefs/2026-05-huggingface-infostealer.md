---
title: Malicious Hugging Face Repository Distributes Information Stealer
slug: 2026-05-huggingface-infostealer
description: A malicious repository on Hugging Face, impersonating OpenAI's 'Privacy Filter' project, distributed information-stealing malware to Windows users by executing a PowerShell command that downloads and runs a Rust-based infostealer, which exfiltrates collected data to a command-and-control server.
date: "2026-05-09T14:26:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - huggingface
  - infostealer
  - malware
  - supply-chain
  - python
  - powershell
  - windows
vendors:
  - OpenAI
  - Hugging Face
  - Microsoft
products:
  - Privacy Filter
  - Microsoft Defender
  - Chromium
  - Gecko
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1573
    technique_name: Encrypted Channel
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1539
    technique_name: Steal Web Session Cookie
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1589
    technique_name: Gather Victim Identity Information
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1069
    technique_name: Standard Permission Assignment
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1033
    technique_name: System Owner/User Discovery
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1047
    technique_name: Windows Management Instrumentation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1615
    technique_name: Impair System Defenses
references:
  - https://www.bleepingcomputer.com/news/security/fake-openai-repository-on-hugging-face-pushes-infostealer-malware/
iocs:
  - type: domain
    value: recargapopular.com
ioc_counts:
  domain: 1
rules:
  - title: Detect Hugging Face Loader Downloads Batch File via Powershell
    description: Detects PowerShell downloading a batch file, start.bat, as part of the Hugging Face infostealer campaign.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1105
    data_sources:
      - process_creation
      - windows
  - title: Detect Hugging Face loader.py Execution
    description: Detects execution of 'loader.py' with suspicious network activity, potentially related to the Hugging Face infostealer campaign.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
      - initial_access
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On May 7, 2026, HiddenLayer researchers discovered a malicious repository on Hugging Face named Open-OSS/privacy-filter that impersonated OpenAI's legitimate "Privacy Filter" project. The repository briefly reached the #1 trending spot on Hugging Face and accumulated 244,000 downloads before being removed. The malicious repository contained a 'loader.py' file that, when executed on Windows machines, fetches and executes information-stealing malware. The malware employs anti-analysis techniques to evade detection. This incident highlights the risk of supply chain attacks targeting AI/ML platforms and the potential for widespread distribution of malware through trusted repositories.

## Attack Chain

1. A user downloads a malicious repository from Hugging Face impersonating OpenAI's "Privacy Filter" project.
2. The user executes the `loader.py` Python script within the downloaded repository.
3. `loader.py` disables SSL verification and decodes a base64 URL, fetching a JSON payload containing a PowerShell command from an external resource.
4. The PowerShell command is executed in an invisible window.
5. The PowerShell command downloads a batch file (`start.bat`).
6. `start.bat` performs privilege escalation.
7. `start.bat` downloads the final payload (sefirah) and adds it to Microsoft Defender's exclusions.
8. `start.bat` executes the final payload, a Rust-based information stealer, which collects and exfiltrates sensitive data to recargapopular[.]com.

## Impact

The exact number of victims is unclear, but the malicious repository accumulated 244,000 downloads. Successful execution of the malware results in the theft of browser data (cookies, saved passwords, encryption keys, browsing data, session tokens), Discord tokens and master keys, cryptocurrency wallets and browser extensions, SSH/FTP/VPN credentials, sensitive local files, system information, and multi-monitor screenshots. The stolen data is then exfiltrated to the attacker's command-and-control server, potentially leading to financial loss, identity theft, and further compromise of affected systems and networks.

## Recommendation

*   Deploy the following Sigma rule to detect the execution of the malicious `loader.py` script that downloads the batch file (start.bat).
*   Block the C2 domain `recargapopular[.]com` listed in the IOC table at the DNS resolver to prevent data exfiltration.
*   Enable Sysmon process creation logging to capture the PowerShell command execution initiated by the Python script, allowing for further investigation (see Sigma rules below).
*   Educate users to verify the authenticity of repositories and files downloaded from Hugging Face and other similar platforms.
