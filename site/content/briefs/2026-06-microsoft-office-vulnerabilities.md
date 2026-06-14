---
title: Multiple Vulnerabilities in Microsoft Office Products (June 2026)
slug: 2026-06-microsoft-office-vulnerabilities
description: CERT-FR has disclosed 31 vulnerabilities in various Microsoft Office products, including CVE-2026-44803 and CVE-2026-47635, which could allow remote code execution, privilege escalation, and data confidentiality compromise.
date: "2026-06-14T09:15:49Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:microsoft:365_apps:-:*:*:*:enterprise:*:x64:*
  - cpe:2.3:a:microsoft:365_apps:-:*:*:*:enterprise:*:x86:*
  - cpe:2.3:a:microsoft:excel:2016:*:*:*:*:*:x64:*
  - cpe:2.3:a:microsoft:excel:2016:*:*:*:*:*:x86:*
  - cpe:2.3:a:microsoft:microsoft_365:-:*:*:*:*:macos:*:*
  - cpe:2.3:a:microsoft:office_2019:-:*:*:*:*:*:x64:*
  - cpe:2.3:a:microsoft:office_2019:-:*:*:*:*:*:x86:*
  - cpe:2.3:a:microsoft:office_2021:-:*:*:*:ltsc:-:x64:*
  - cpe:2.3:a:microsoft:office_2021:-:*:*:*:ltsc:-:x86:*
  - cpe:2.3:a:microsoft:office_2021:-:*:*:*:ltsc:macos:-:*
  - cpe:2.3:a:microsoft:office_2024:-:*:*:*:ltsc:-:x64:*
  - cpe:2.3:a:microsoft:office_2024:-:*:*:*:ltsc:-:x86:*
  - cpe:2.3:a:microsoft:office_2024:-:*:*:*:ltsc:macos:-:*
  - cpe:2.3:a:microsoft:office_online_server:-:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:office_2016:-:*:*:*:-:*:x64:*
  - cpe:2.3:a:microsoft:office_2016:-:*:*:*:-:*:x86:*
  - cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:subscription:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:2016:*:*:*:enterprise:*:*:*
  - cpe:2.3:a:microsoft:sharepoint_server:2019:*:*:*:*:*:*:*
tags:
  - vulnerability
  - microsoft-office
  - remote-code-execution
  - privilege-escalation
  - data-confidentiality
  - windows
  - macos
  - android
vendors:
  - Microsoft
products:
  - Microsoft 365 Apps pour Enterprise pour systèmes 32 bits
  - Microsoft 365 Apps pour Enterprise pour systèmes 64 bits
  - Microsoft Excel 2016 (édition 32 bits) versions antérieures à 16.0.5556.1001
  - Microsoft Excel 2016 (édition 64 bits) versions antérieures à 16.0.5556.1001
  - Microsoft Excel pour Android
  - Microsoft Office 2016 (édition 32 bits) versions antérieures à 16.0.5556.1005
  - Microsoft Office 2016 (édition 64 bits) versions antérieures à 16.0.5556.1005
  - Microsoft Office 2019 pour éditions 32 bits
  - Microsoft Office 2019 pour éditions 64 bits
  - Microsoft Office 365 pour Mac
  - Microsoft Office LTSC 2021 pour éditions 32 bits
  - Microsoft Office LTSC 2021 pour éditions 64 bits
  - Microsoft Office LTSC 2024 pour éditions 32 bits
  - Microsoft Office LTSC 2024 pour éditions 64 bits
  - Microsoft Office LTSC pour Mac 2021
  - Microsoft Office LTSC pour Mac 2024
  - Microsoft Office pour Android
  - Microsoft PowerPoint pour Android
  - Microsoft Word 2016 (édition 32 bits) versions antérieures à 16.0.5556.1000
  - Microsoft Word 2016 (édition 64 bits) versions antérieures à 16.0.5556.1000
  - Microsoft Word pour Android
  - Office Online Server versions antérieures à 16.0.10417.20137
affected_os:
  - Windows
  - macOS
  - Android
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
cves:
  - id: CVE-2026-44803
    cvss: 7.8
    epss: 0.001
  - id: CVE-2026-44818
    cvss: 7
    epss: 0.00041
  - id: CVE-2026-44819
    cvss: 7.8
    epss: 0.00079
  - id: CVE-2026-45469
    cvss: 7.8
    epss: 0.001
  - id: CVE-2026-45475
    cvss: 7.8
    epss: 0.00079
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0727/
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44803
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44812
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44817
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44818
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44819
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44820
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44821
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44822
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44823
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44824
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45455
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45456
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45457
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45458
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45459
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45460
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45461
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45463
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45466
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45469
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45471
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45472
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45474
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45475
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45485
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45486
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45643
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45645
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-45649
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47293
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47635
  - https://www.cve.org/CVERecord?id=CVE-2026-44803
  - https://www.cve.org/CVERecord?id=CVE-2026-44812
  - https://www.cve.org/CVERecord?id=CVE-2026-44817
  - https://www.cve.org/CVERecord?id=CVE-2026-44818
  - https://www.cve.org/CVERecord?id=CVE-2026-44819
  - https://www.cve.org/CVERecord?id=CVE-2026-44820
  - https://www.cve.org/CVERecord?id=CVE-2026-44821
  - https://www.cve.org/CVERecord?id=CVE-2026-44822
  - https://www.cve.org/CVERecord?id=CVE-2026-44823
  - https://www.cve.org/CVERecord?id=CVE-2026-44824
  - https://www.cve.org/CVERecord?id=CVE-2026-45455
  - https://www.cve.org/CVERecord?id=CVE-2026-45456
  - https://www.cve.org/CVERecord?id=CVE-2026-45457
  - https://www.cve.org/CVERecord?id=CVE-2026-45458
  - https://www.cve.org/CVERecord?id=CVE-2026-45459
  - https://www.cve.org/CVERecord?id=CVE-2026-45460
  - https://www.cve.org/CVERecord?id=CVE-2026-45461
  - https://www.cve.org/CVERecord?id=CVE-2026-45463
  - https://www.cve.org/CVERecord?id=CVE-2026-45466
  - https://www.cve.org/CVERecord?id=CVE-2026-45469
  - https://www.cve.org/CVERecord?id=CVE-2026-45471
  - https://www.cve.org/CVERecord?id=CVE-2026-45472
  - https://www.cve.org/CVERecord?id=CVE-2026-45474
  - https://www.cve.org/CVERecord?id=CVE-2026-45475
  - https://www.cve.org/CVERecord?id=CVE-2026-45485
  - https://www.cve.org/CVERecord?id=CVE-2026-45486
  - https://www.cve.org/CVERecord?id=CVE-2026-45643
  - https://www.cve.org/CVERecord?id=CVE-2026-45645
  - https://www.cve.org/CVERecord?id=CVE-2026-45649
  - https://www.cve.org/CVERecord?id=CVE-2026-47293
  - https://www.cve.org/CVERecord?id=CVE-2026-47635
rules:
  - title: Detect Suspicious Child Process by Microsoft Office Application
    description: Detects Microsoft Office applications (Word, Excel, PowerPoint) spawning suspicious child processes often indicative of remote code execution or macro-based attacks.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1204
    data_sources:
      - process_creation
      - windows
  - title: Detect Outbound Network Connection from Microsoft Office Application
    description: Detects Microsoft Office applications making outbound network connections, which can indicate command-and-control activity or data exfiltration following exploitation of CVE-2026-44803 or other RCE vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1041
      - T1071
    data_sources:
      - network_connection
      - windows
  - title: Detect Microsoft Office Application Creating Executable Files
    description: Detects Microsoft Office applications (Word, Excel, PowerPoint) creating potentially malicious executable or script files in user-writable or system temporary directories, indicating post-exploitation activity like malware drops from CVE-2026-44803.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - persistence
    techniques:
      - T1204.002
    data_sources:
      - file_event
      - windows
rules_count: 3
---

CERT-FR has released an advisory detailing 31 critical and high-severity vulnerabilities affecting numerous Microsoft Office products. These vulnerabilities, identified by CVEs such as CVE-2026-44803 (the first listed) and CVE-2026-47635 (the last listed), were disclosed by Microsoft on June 9, 2026. The flaws impact a wide range of Office applications, including Microsoft 365 Apps, various versions of Excel, Word, PowerPoint, and Office Online Server, across Windows, macOS, and Android platforms. Successful exploitation of these vulnerabilities could lead to arbitrary remote code execution, elevation of privileges on affected systems, and unauthorized access to sensitive data, posing a significant risk to organizational assets. While no specific threat actors or active exploitation campaigns are detailed in the advisory, these types of vulnerabilities are frequently targeted by advanced persistent threats and opportunistic attackers.

## Attack Chain

1.  **Initial Access**: A user receives and opens a specially crafted Microsoft Office document (e.g., Word, Excel, or PowerPoint file) delivered via a phishing email, malicious download, or other social engineering methods.
2.  **Exploitation**: The malicious document leverages one of the disclosed vulnerabilities (e.g., CVE-2026-44803) within the vulnerable Microsoft Office application upon opening or specific user interaction.
3.  **Remote Code Execution**: Successful exploitation results in remote code execution (RCE) within the context of the compromised Office application process, allowing the attacker to execute arbitrary commands.
4.  **Payload Delivery**: The executed code downloads and executes additional malicious payloads (e.g., malware droppers, backdoors, or command-and-control agents) from an external attacker-controlled server.
5.  **Privilege Escalation**: The attacker may then exploit another vulnerability (e.g., CVE-2026-44812) or leverage a misconfiguration to escalate privileges, gaining higher system access on the compromised host.
6.  **Objective Achievement**: With elevated privileges and persistent access, the attacker can proceed with their objectives, which may include lateral movement across the network, exfiltration of sensitive data, further system compromise, or deployment of additional malicious software.

## Impact

The successful exploitation of these vulnerabilities could have severe consequences for affected organizations. Attackers could gain complete control over compromised systems, leading to extensive data breaches, operational disruption, and the deployment of ransomware or other destructive malware. While the advisory does not specify the number of victims or targeted sectors, the broad impact across common Microsoft Office products means that organizations of all sizes and industries are potentially at risk. The combination of remote code execution, privilege escalation, and data confidentiality compromise could lead to significant financial losses, reputational damage, and regulatory penalties.

## Recommendation

*   Patch CVE-2026-44803, CVE-2026-44812, CVE-2026-44817, CVE-2026-44818, CVE-2026-44819, CVE-2026-44820, CVE-2026-44821, CVE-2026-44822, CVE-2026-44823, CVE-2026-44824, CVE-2026-45455, CVE-2026-45456, CVE-2026-45457, CVE-2026-45458, CVE-2026-45459, CVE-2026-45460, CVE-2026-45461, CVE-2026-45463, CVE-2026-45466, CVE-2026-45469, CVE-2026-45471, CVE-2026-45472, CVE-2026-45474, CVE-2026-45475, CVE-2026-45485, CVE-2026-45486, CVE-2026-45643, CVE-2026-45645, CVE-2026-45649, CVE-2026-47293, and CVE-2026-47635 by applying the latest security updates from Microsoft for all affected Office products and versions immediately.
*   Deploy the "Detect Suspicious Child Process by Microsoft Office Application" Sigma rule to detect post-exploitation activity from Office applications.
*   Deploy the "Detect Outbound Network Connection from Microsoft Office Application" Sigma rule to monitor for unusual C2 communications.
*   Ensure Sysmon process creation (Event ID 1), network connection (Event ID 3), and file creation (Event ID 11) logging is enabled on all Windows endpoints to generate the necessary telemetry for the detection rules in this brief.
