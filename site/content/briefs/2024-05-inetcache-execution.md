---
title: Suspicious Execution from INetCache Folder
slug: 2024-05-inetcache-execution
description: The rule detects suspicious execution of processes from the INetCache folder, often indicative of malicious payloads delivered via WININET, potentially signaling initial access or command and control activity.
date: "2024-05-01T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - initial-access
  - command-and-control
  - execution
  - inetcache
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2024-21412
    cvss: 8.1
    epss: 0.95443
references:
  - https://www.trendmicro.com/en_us/research/24/b/cve202421412-water-hydra-targets-traders-with-windows-defender-s.html
  - https://attack.mitre.org/techniques/T1566/
  - https://attack.mitre.org/techniques/T1566/001/
  - https://attack.mitre.org/techniques/T1105/
  - https://attack.mitre.org/tactics/TA0011/
  - https://attack.mitre.org/techniques/T1204/
  - https://attack.mitre.org/techniques/T1204/002/
rules:
  - title: Suspicious Execution from INetCache Folder
    description: Detects execution of a process with arguments or executable path pointing to the INetCache folder.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - execution
      - initial_access
    techniques:
      - T1105
      - T1204
      - T1566
    data_sources:
      - process_creation
      - windows
  - title: Suspicious Process Creation with INetCache Path in Sysmon
    description: Detects process creation events where the image path contains the INetCache directory, using Sysmon event data.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This threat brief addresses the risk of malicious actors leveraging the INetCache folder for executing malware. The INetCache folder, used for storing temporary internet files, can be exploited to deliver and execute malicious payloads via WININET. This technique is used by attackers to disguise malware as legitimate files cached during browsing, making it difficult for users to identify malicious activity. This rule focuses on detecting suspicious processes initiated from this cache, especially when launched by common file explorers, which often signifies initial access or command and control activities. A recent Trend Micro report has associated this technique with the Water Hydra threat actor who have been observed exploiting this vector (CVE-2024-21412).

## Attack Chain

1.  User browses a compromised website or opens a malicious document containing a link.
2.  The website or document triggers the download of a malicious executable to the INetCache folder.
3.  The user inadvertently clicks on the downloaded file within the INetCache folder, often disguised as a legitimate file.
4.  Alternatively, a parent process like `explorer.exe`, `winrar.exe`, `7zFM.exe`, or `Bandizip.exe` is used to execute the malicious file from the INetCache folder.
5.  The malicious executable runs, establishing a connection to a command and control (C2) server.
6.  The C2 server sends commands to the compromised host, allowing the attacker to perform actions such as data exfiltration, lateral movement, or deploying additional malware.
7.  The attacker uses the compromised system to gain further access to the internal network.

## Impact

Successful exploitation leads to initial access and potential command and control over the compromised system. This can result in data theft, deployment of ransomware, or further propagation within the network. Given the wide use of WININET and web browsing, many Windows systems are potentially vulnerable. The Trend Micro report (CVE-2024-21412) indicates this technique is being actively used in targeted attacks, highlighting the immediate need for detection and prevention measures.

## Recommendation

*   Deploy the Sigma rule `Suspicious Execution from INetCache Folder` to detect processes executing from the INetCache directory.
*   Enable Sysmon process creation logging to capture the necessary process execution events for the Sigma rule.
*   Implement enhanced monitoring for the INetCache directory and related processes as described in the rule's documentation.
*   Investigate and patch CVE-2024-21412 to prevent the Water Hydra campaign.
