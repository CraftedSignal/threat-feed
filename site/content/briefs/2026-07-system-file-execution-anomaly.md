---
title: System File Execution Location Anomaly
slug: 2026-07-system-file-execution-anomaly
description: This brief describes the detection of Windows system binaries executing from uncommon locations, a defense evasion and stealth technique employed by various threat actors including Lazarus Group and Sidewinder APT, indicating potential malicious activity on an endpoint.
date: "2026-07-08T23:28:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Lazarus Group
  - HIDDEN COBRA
  - LABYRINTH CHOLLIMA
  - Diamond Sleet
  - Zinc
  - Sidewinder APT
tags:
  - defense-evasion
  - stealth
  - execution
  - windows
  - process-anomaly
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Detects the execution of a Windows system binary that is usually located in the system folder from an uncommon location.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Dfrgui.exe was seen used by Lazarus Group - https://asec.ahnlab.com/en/39828/.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Wsmprovhost.exe was seen used by Lazarus Group - https://asec.ahnlab.com/en/39828/.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
    evidence: Fsquirt.exe was seen used by sidewinder APT - https://securelist.com/sidewinder-apt/114089/.
    confidence_band: high
references:
  - https://twitter.com/GelosSnake/status/934900723426439170
  - https://asec.ahnlab.com/en/39828/
  - https://www.splunk.com/en_us/blog/security/inno-setup-malware-redline-stealer-campaign.html
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/process_creation/proc_creation_win_susp_system_exe_anomaly.yml
rules:
  - title: System File Execution Location Anomaly
    description: Detects the execution of a Windows system binary that is usually located in the system folder from an uncommon location, indicating potential defense evasion or stealth techniques.
    platform: sigma
    severity: high
    tactics:
      - stealth
    techniques:
      - T1036
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

This threat brief focuses on detecting anomalous executions of standard Windows system binaries from non-standard or unexpected file system locations. While these binaries (such as `certutil.exe`, `dfrgui.exe`, `svchost.exe`, `wsmprovhost.exe`) are legitimate components of the operating system, their execution from directories outside of `C:\Windows\System32\` or other designated system paths is highly suspicious. Threat actors, including groups like Lazarus Group and Sidewinder APT, leverage this technique for defense evasion and stealth, attempting to blend malicious activity with legitimate system processes. By relocating and executing these binaries, adversaries can bypass security controls that only monitor typical system paths, establish persistence, load malicious modules, or achieve other post-exploitation objectives, making their activities harder to detect. This anomaly indicates an active compromise and warrants immediate investigation.

## Attack Chain

1. **Initial Access**: Attacker gains initial access to a system, typically through phishing, exploitation of a public-facing application, or compromised credentials.
2. **Payload Delivery**: A malicious payload (e.g., a custom tool, a stealer, or a loader) is delivered to the victim's machine, often written to a temporary or user-controlled directory like `C:\ProgramData\` or `C:\Users\Public\`.
3. **Staging System Binaries**: The attacker copies a legitimate Windows system binary (e.g., `certutil.exe`, `dfrgui.exe`, `wsmprovhost.exe`) from its standard location (e.g., `C:\Windows\System32\`) to a non-standard directory under their control.
4. **Malicious Execution**: The attacker executes the copied system binary from the anomalous location, often to perform a specific task such as decoding a payload, loading a malicious DLL, or executing commands.
5. **Defense Evasion & Stealth**: Running these binaries from unusual paths helps the attacker evade detection by security tools that are configured to only monitor standard system locations for these processes, creating a blind spot.
6. **Further Compromise**: The execution facilitates subsequent attack stages, which could include privilege escalation, lateral movement, data exfiltration, or the deployment of ransomware.
7. **Persistence**: The attacker may configure the executed binary to restart or perform tasks persistently by modifying startup locations or scheduled tasks.

## Impact

Successful exploitation using this technique can lead to significant compromise of affected systems and data. By using legitimate system binaries from unusual locations, attackers achieve a higher degree of stealth, making their activities more challenging for defenders to identify. This can result in prolonged dwell times, enabling comprehensive network reconnaissance, extensive data exfiltration, and establishment of resilient persistence mechanisms. The ultimate impact can range from the theft of sensitive intellectual property and credentials to the complete disruption of critical business operations through ransomware deployment. Specific incidents have shown groups like Lazarus Group leveraging this for information stealing and further network compromise.

## Recommendation

* Deploy the Sigma rule `System File Execution Location Anomaly` to your SIEM and tune for your environment to detect suspicious executions.
* Ensure process creation logging is enabled across all Windows endpoints, specifically for `Image` and `CommandLine` fields, to provide telemetry for the `process_creation` log source.
* Investigate all alerts generated by the `System File Execution Location Anomaly` rule, paying close attention to the full path of the executed image and its parent process.
* Implement application control mechanisms (e.g., Windows Defender Application Control, AppLocker) to restrict execution of binaries from non-standard locations, especially for critical system components.
