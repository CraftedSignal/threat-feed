---
title: PowerShell Suspicious Payload Encoded and Compressed
slug: 2024-01-powershell-compressed-payload
description: Attackers use PowerShell to execute Base64 encoded and .NET compressed payloads (Deflate/GZip) to evade defenses by deobfuscating and reconstructing payloads in memory.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - powershell
  - base64
  - compression
vendors:
  - Microsoft
products:
  - Windows Defender Advanced Threat Protection
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/defense_evasion_posh_compressed.toml
rules:
  - title: PowerShell Suspicious Payload Encoded and Compressed
    description: Detects PowerShell script block content that combines Base64 decoding with .NET decompression (Deflate/GZip).
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
  - title: PowerShell Suspicious Compressed Stream Usage
    description: Detects PowerShell script blocks using compression streams.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers are increasingly using PowerShell to deliver obfuscated and compressed payloads to evade traditional signature-based detection. This technique involves encoding a malicious payload using Base64 and then compressing it with .NET compression methods like Deflate or Gzip. By combining these methods, attackers can significantly reduce the size and increase the complexity of their payloads, making it more difficult for security tools to detect malicious code. The observed activity leverages the `System.IO.Compression` namespace within PowerShell to perform the decompression. This behavior aims to bypass defenses by reconstructing the payload in memory, minimizing the footprint on disk. The rule `PowerShell Suspicious Payload Encoded and Compressed` was updated on 2026-04-30 to detect this obfuscation technique.

## Attack Chain

1. An attacker gains initial access to a system, often through phishing or exploitation of a vulnerability.
2. The attacker executes a PowerShell script, either through a file or directly in memory, using `powershell.exe`.
3. The PowerShell script contains a compressed and Base64-encoded payload.
4. The script utilizes .NET methods such as `System.IO.Compression.DeflateStream` or `System.IO.Compression.GzipStream` to decompress the payload.
5. The script uses the `FromBase64String` method to decode the Base64-encoded data.
6. The decoded and decompressed payload is then reconstructed in memory.
7. The reconstructed payload is executed using techniques like `Invoke-Expression` or similar methods to achieve code execution.
8. The attacker achieves their objective, such as installing malware, establishing persistence, or exfiltrating data.

## Impact

Successful exploitation allows attackers to bypass security controls and execute arbitrary code on compromised systems. This can lead to data breaches, system compromise, and potential lateral movement within the network. The obfuscation makes incident response more complex, as analysts must first deobfuscate the code before analysis. The impact of such attacks can range from data theft to complete system compromise, depending on the attacker's objectives and the value of the targeted data.

## Recommendation

*   Enable PowerShell Script Block Logging to capture the full content of executed scripts (`powershell.file.script_block_text`).
*   Deploy the Sigma rule "PowerShell Suspicious Payload Encoded and Compressed" to detect the described behavior. Tune the entropy threshold (`powershell.file.script_block_entropy_bits`) for your environment.
*   Investigate PowerShell processes with high script block entropy and usage of `System.IO.Compression.DeflateStream`, `System.IO.Compression.GzipStream` and `FromBase64String` to identify potential malicious activity.
*   Monitor process execution and network connections originating from PowerShell processes executing suspicious compressed and encoded payloads.
