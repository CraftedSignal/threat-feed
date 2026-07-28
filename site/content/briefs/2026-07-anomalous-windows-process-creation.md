---
title: Anomalous Windows Process Creation Detected by Machine Learning
slug: 2026-07-anomalous-windows-process-creation
description: 'Elastic Security''s machine learning rule `v3_windows_anomalous_process_creation_ea` detects unusual parent-child process relationships on Windows systems, indicating potential malware execution or persistence mechanisms and allowing for early detection of new or emerging threats that bypass traditional antivirus. '
date: "2026-07-28T18:45:22Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - endpoint
  - windows
  - machine-learning
  - persistence
  - execution
  - anomaly-detection
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Identifies unusual parent-child process relationships that can indicate malware execution or persistence mechanisms.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Excel or Word may start a script interpreter process, which, in turn, runs a script that downloads and executes malware.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/ml/persistence_ml_windows_anomalous_process_creation.toml
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
---

Elastic Security's machine learning rule `v3_windows_anomalous_process_creation_ea` identifies unusual parent-child process relationships on Windows systems. This detection mechanism helps defenders spot new and emerging malware that might bypass traditional antivirus solutions by flagging anomalous process creation events, such as legitimate applications like Microsoft Office programs or Outlook spawning unexpected script interpreters (e.g., PowerShell, cmd.exe) or other binaries. These anomalies are strong indicators of malware execution, persistence mechanisms, or exploit payloads being delivered. The rule uses entity analytics (EA) fields and has a low severity, suggesting it's designed for broad baseline monitoring across the enterprise to establish a baseline of normal behavior and flag deviations.

## Attack Chain

1. **Initial Access / Execution**: An attacker gains initial access, often via a malicious document, email attachment, or exploit, leading to execution on the victim's system.
2. **Legitimate Application Launch**: A benign, user-facing application (e.g., Microsoft Word, Excel, Outlook) is launched as part of the initial access vector.
3. **Anomalous Child Process Creation**: The legitimate application then spawns an unusual or unexpected child process, which deviates from established normal behavior for that parent-child relationship.
4. **Script Interpreter Execution**: This unexpected child process is often a script interpreter (e.g., `powershell.exe`, `cmd.exe`, `wscript.exe`), launched to execute a malicious script or command.
5. **Malware Delivery/Execution**: The script then downloads, decrypts, or directly executes additional malicious payloads (e.g., ransomware, infostealers, remote access tools).
6. **Persistence Establishment**: The deployed malware may then attempt to establish persistence on the compromised system using various techniques, further leveraging unusual process creation.
7. **Machine Learning Detection**: The `v3_windows_anomalous_process_creation_ea` machine learning model detects the anomalous parent-child process relationship as a deviation from the learned normal behavior baseline.

## Impact

The successful exploitation indicated by anomalous process creation can lead to various forms of system compromise, including unauthorized code execution, malware installation, establishment of persistence, and potential data exfiltration or encryption. Since this detection targets general anomalous behavior, the specific impact varies depending on the attacker's ultimate objective and the malware deployed. Early detection through this machine learning rule aims to prevent the progression of attacks that leverage novel execution and persistence techniques, thereby mitigating broader organizational damage, data breaches, and financial losses.

## Recommendation

* Deploy the Elastic Machine Learning job `v3_windows_anomalous_process_creation_ea` as detailed in the setup instructions for this rule.
* Ensure Elastic Defend is fully integrated and configured for 'Complete EDR' to provide comprehensive endpoint telemetry for analysis to the Elastic Security platform.
* Enable the Windows integration in Elastic Agent to collect relevant process and event logs from endpoints.
* Investigate alerts from `Anomalous Windows Process Creation` by examining the process execution chain and associated metadata, including digital signatures and file paths.
* Utilize Osquery commands, such as those provided for DNS cache, services, and unsigned executables, during investigation to gather additional host context.
* Analyze suspicious executables in a private sandboxed environment and check SHA-256 hashes against public threat intelligence sources like VirusTotal.
