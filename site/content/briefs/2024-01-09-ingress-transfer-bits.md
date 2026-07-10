---
title: Ingress Transfer via Windows BITS
slug: 2024-01-09-ingress-transfer-bits
description: Adversaries leverage the Windows Background Intelligent Transfer Service (BITS) to download executable and archive files, potentially delivering malicious payloads while evading traditional security measures.
date: "2024-01-09T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - bits
  - file-transfer
  - windows
  - command-and-control
  - defense-evasion
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1197
    technique_name: BITS Jobs
references:
  - https://attack.mitre.org/techniques/T1197/
rules:
  - title: Detect Ingress Transfer via Windows BITS Renaming
    description: Detects the renaming of files downloaded via BITS, indicating a potential malware delivery.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
      - T1197
    data_sources:
      - file_event
      - windows
  - title: Detect BITSAdmin Tool Execution
    description: Detects the execution of BITSAdmin, a command-line tool used to manage BITS transfers.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1197
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Attackers may abuse the Windows Background Intelligent Transfer Service (BITS) to transfer malicious files to a compromised system. BITS is a legitimate Windows service used to transfer files asynchronously in the background, which makes it a useful tool for adversaries looking to download malware or exfiltrate data without attracting attention. This technique, known as "Ingress Tool Transfer" (T1105), can be used to deliver payloads such as executables, archives, or scripts. The detection focuses on file rename events involving `svchost.exe` (the generic host process for Windows services, including BITS) and temporary files with the `BIT*.tmp` naming convention. This activity is often associated with BITS transfers, allowing defenders to identify potentially malicious downloads. This technique allows attackers to use a trusted Windows process to perform malicious actions, bypassing some security controls and potentially blending in with legitimate system activity.

## Attack Chain

1. The attacker gains initial access to the system through an unrelated method (e.g., phishing, exploit).
2. The attacker leverages the BITSAdmin tool or equivalent API calls to create a BITS job.
3. The BITS job is configured to download a malicious payload from a remote server.
4. The BITS service (`svchost.exe`) initiates a network connection to the attacker's server.
5. The malicious payload is downloaded and saved as a temporary file with a `BIT*.tmp` extension.
6. Upon completion of the download, the temporary file is renamed to its final intended name, often an executable or archive file.
7. The attacker executes the downloaded payload, leading to further compromise of the system.
8. The attacker achieves their final objective, such as establishing persistence, escalating privileges, or deploying ransomware.

## Impact

Successful exploitation allows attackers to introduce malware or other malicious tools onto the targeted system. This can lead to a variety of negative consequences, including data theft, system compromise, and network disruption. The use of BITS can make detection more difficult, as the downloads are performed by a legitimate Windows service. The scope of impact varies depending on the specific payload delivered via BITS, but could include complete system takeover.

## Recommendation

*   Deploy the Sigma rule "Detect Ingress Transfer via Windows BITS Renaming" to identify suspicious file rename events associated with BITS downloads based on the `file.Ext.original.name : "BIT*.tmp"` and `process.name : "svchost.exe"` artifacts.
*   Monitor network connections initiated by `svchost.exe`, specifically looking for connections to unusual or suspicious domains, as highlighted in the investigation guide section of the brief.
*   Enable Sysmon file creation and process creation logging to improve visibility into BITS activity and activate the Sigma rules.
*   Investigate any instances of `bitsadmin.exe` being executed, paying close attention to the command-line arguments, as mentioned in the triage and analysis section.
*   Consider using a tool like BitsParser to extract BITS job information from the BITS database files for deeper analysis, as referenced in the investigation guide.
