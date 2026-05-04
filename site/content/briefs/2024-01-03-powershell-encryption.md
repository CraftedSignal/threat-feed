---
title: PowerShell Script with Encryption/Decryption Capabilities
slug: 2024-01-03-powershell-encryption
description: PowerShell scripts employing .NET cryptography APIs are used to encrypt data for impact or decrypt payloads for defense evasion.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - powershell
  - encryption
  - defense-evasion
  - windows
vendors:
  - Elastic
  - Octopus Deploy
products:
  - Elastic Endpoint Security
  - Octopus Deploy
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1140
    technique_name: Deobfuscate/Decode Files or Information
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1486
    technique_name: Data Encrypted for Impact
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_posh_encryption.toml
  - https://attack.mitre.org/techniques/T1027/
  - https://attack.mitre.org/techniques/T1027/013/
  - https://attack.mitre.org/techniques/T1140/
  - https://attack.mitre.org/techniques/T1486/
  - https://ela.st/powershell-logging-setup
rules:
  - title: PowerShell Encryption API Usage
    description: Detects PowerShell scripts using .NET encryption APIs
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
      - T1027.013
      - T1140
      - T1486
    data_sources:
      - process_creation
      - windows
  - title: PowerShell Script Block Logging - Encryption Routines
    description: Detects PowerShell script blocks that contain encryption or decryption routines.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
      - T1027.013
      - T1140
      - T1486
    data_sources:
      - powershell
      - windows
rules_count: 2
---

This threat brief focuses on the detection of PowerShell scripts utilizing .NET cryptography APIs for file encryption or decryption. Attackers often leverage these capabilities to encrypt data for impact, potentially leading to data exfiltration or ransomware deployment, or to decrypt staged payloads, circumventing traditional security measures. Defenders should be aware of PowerShell scripts employing symmetric cryptography classes (AES/Rijndael, SymmetricAlgorithm), key derivation helpers (PasswordDeriveBytes, Rfc2898DeriveBytes), explicit cipher configurations (CipherMode, PaddingMode), and functions that generate encryptors/decryptors. Identifying such scripts is crucial for preventing both data compromise and the execution of malicious payloads. This detection specifically targets Windows systems where PowerShell is commonly used for both legitimate administration and malicious activities.

## Attack Chain

1.  Attacker gains initial access to the target system (e.g., via compromised credentials or a phishing attack).
2.  Attacker uploads or stages a PowerShell script containing encryption/decryption capabilities.
3.  The PowerShell script utilizes .NET cryptography APIs (e.g., `AESManaged`, `RijndaelManaged`, `PasswordDeriveBytes`, `Rfc2898DeriveBytes`).
4.  The script configures the cipher using `CipherMode` and `PaddingMode`.
5.  The script invokes `.CreateEncryptor()` or `.CreateDecryptor()` methods to initialize the cryptographic operation.
6.  If encrypting, the script iterates through target files, encrypting their content and potentially renaming or deleting originals.
7.  If decrypting, the script processes an encrypted payload, converting it to executable form or writing it to a new artifact.
8.  The attacker executes the decrypted payload or exfiltrates the encrypted data, completing their objective.

## Impact

Successful exploitation can lead to significant data loss, system downtime, and financial damage. Data encryption for impact can render systems unusable, while the decryption of staged payloads can introduce malware into the environment. The number of victims can vary widely depending on the scope of the attack, ranging from individual workstations to entire networks. Targeted sectors may include any organization reliant on Windows-based systems, with potential consequences including operational disruption, reputational damage, and regulatory fines.

## Recommendation

*   Enable PowerShell Script Block Logging to capture the events required for detection, specifically event ID 4104, as detailed in the [Elastic PowerShell logging setup guide](https://ela.st/powershell-logging-setup).
*   Deploy the Sigma rule `PowerShell Script with Encryption/Decryption Capabilities` to your SIEM to detect suspicious PowerShell scripts utilizing .NET cryptography APIs.
*   Investigate alerts triggered by the Sigma rule, focusing on `powershell.file.script_block_text` to understand the cryptographic intent and data flow.
*   Tune the Sigma rule by adding exceptions for legitimate PowerShell scripts that use encryption, referencing the "False positive analysis" section in this brief.
