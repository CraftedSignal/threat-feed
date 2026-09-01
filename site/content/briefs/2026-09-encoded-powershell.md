---
title: Suspicious PowerShell Base64 Encoded Command Lines
slug: 2026-09-encoded-powershell
description: Detection of malicious PowerShell execution patterns involving Base64 encoded commands, frequently utilized by malware families such as Emotet for obfuscated payload delivery.
date: "2026-09-01T12:22:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - powershell
  - obfuscation
  - execution
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Detects suspicious powershell process starts with base64 encoded commands
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml
  - https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e
rules:
  - title: Detect Suspicious Encoded PowerShell Command Line
    description: Detects PowerShell process starts with Base64 encoded commands often associated with malware such as Emotet.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy the encoded PowerShell detection rule to the SIEM
      owner: Detection Engineering
      due: 48h
      evidence: Source provides high-fidelity logic for detecting PowerShell obfuscation
  hunt_leads:
    - lead: Search for processes spawned by non-interactive service accounts using -enc or -e switches
      technique_id: T1059.001
      data_needed:
        - Process creation telemetry
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: PowerShell encoding is commonly used to mask malicious activity
---

This brief addresses a common technique used by attackers to execute obfuscated PowerShell scripts on Windows systems. By utilizing Base64 encoding for command-line arguments, attackers attempt to bypass static analysis tools and signature-based security controls. This method is a hallmark of various malware families, most notably Emotet, which leverages PowerShell to bootstrap secondary payloads, establish persistence, or perform reconnaissance. Attackers typically use the -EncodedCommand or shorthand -e switches to pass malicious scripts that are reconstructed in memory at runtime. Given the ubiquity of PowerShell in administrative environments, detection must focus on common encoding patterns and indicators of shell reconstruction to distinguish malicious activity from standard system maintenance tasks.

## Attack Chain

1. Initial infection (e.g., via phishing document) triggers an external process, often mshta.exe or wscript.exe.
2. The initial process executes a command-line string containing a Base64 encoded PowerShell script.
3. The operating system spawns a new PowerShell (powershell.exe) or PowerShell Core (pwsh.exe) process.
4. The process ingest the encoded argument, often hidden with flags to prevent user notification.
5. The PowerShell engine decodes the Base64 input buffer into executable code.
6. The decoded script performs environment checks, C2 connection establishment, or privilege escalation.
7. The final stage executes the primary payload (e.g., banking trojan or credential harvester) in memory.

## Impact

Successful execution of these encoded commands often results in full system compromise, providing attackers with a foothold for credential theft, lateral movement, and data exfiltration. Because the malicious logic is decoded directly in memory, it poses a significant challenge for traditional file-based antivirus solutions that do not perform behavioral memory analysis.

## Recommendation

- Deploy the provided Sigma rule to detect PowerShell processes launching with known Base64 command-line patterns.
- Enable PowerShell Script Block Logging (Event ID 4104) to capture the de-obfuscated script content, providing visibility into the decoded logic even when the initial command line is encoded.
- Review environments for high-frequency PowerShell usage from non-administrative service accounts to refine the baseline for detection tuning.
