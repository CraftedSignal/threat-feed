---
title: Suspicious File Creation by Microsoft Exchange Unified Messaging Service
slug: 2024-01-03-exchange-um-webshell
description: This rule detects suspicious file creations by the Microsoft Exchange Server Unified Messaging service, potentially indicative of exploitation of CVE-2021-26858, leading to web shell deployment for initial access, lateral movement, and persistence.
date: "2024-01-03T18:12:00Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - exchange
  - webshell
  - cve-2021-26858
  - initial-access
vendors:
  - Microsoft
products:
  - Microsoft Exchange Server
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
cves:
  - id: CVE-2021-26858
    cvss: 7.8
    epss: 0.89509
references:
  - https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers
  - https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities
  - https://github.com/microsoft/CSS-Exchange/tree/main/Security/Baselines
  - https://attack.mitre.org/techniques/T1190/
  - https://attack.mitre.org/techniques/T1210/
  - https://attack.mitre.org/techniques/T1505/
  - https://attack.mitre.org/techniques/T1505/003/
rules:
  - title: Microsoft Exchange Server UM Writing Suspicious Files
    description: Detects suspicious file creations by the Microsoft Exchange Server Unified Messaging service, potentially indicative of web shell deployment following CVE-2021-26858 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - lateral_movement
      - persistence
    techniques:
      - T1190
      - T1210
      - T1505
      - T1505.003
    data_sources:
      - file_event
      - windows
  - title: Suspicious File Creation in Exchange VDir
    description: Detects generic suspicious file creations in Exchange virtual directories.
    platform: sigma
    severity: low
    tactics:
      - initial_access
      - lateral_movement
      - persistence
    techniques:
      - T1190
      - T1210
      - T1505
      - T1505.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

This detection focuses on identifying suspicious file creation events triggered by the Microsoft Exchange Server Unified Messaging (UM) service, specifically `UMWorkerProcess.exe` and `umservice.exe`. The activity is linked to potential exploitation of CVE-2021-26858, a server-side request forgery (SSRF) vulnerability. The rule targets the creation of files with web-related extensions such as `php`, `jsp`, `js`, `aspx`, `asmx`, `asax`, `cfm`, and `shtml` within specific Microsoft Exchange Server directories. Successful exploitation allows attackers to establish a web shell, gaining unauthorized access, enabling lateral movement, and achieving persistence within the compromised environment. This activity was observed beginning in early 2021, with widespread targeting of Exchange servers.

## Attack Chain

1.  Attacker exploits CVE-2021-26858 or similar vulnerability in Exchange Server, gaining the ability to write arbitrary files.
2.  The Exchange UM service (`UMWorkerProcess.exe` or `umservice.exe`) is leveraged to write malicious files.
3.  A web shell file (e.g., `malware.aspx`, `backdoor.php`) is created in a directory accessible via HTTP, such as `\inetpub\wwwroot\aspnet_client\`, `*\Microsoft\Exchange Server*\FrontEnd\HttpProxy\owa\auth\`, or `*\Microsoft\Exchange Server*\FrontEnd\HttpProxy\ecp\auth\`.
4.  The attacker accesses the web shell via a web browser, sending HTTP requests to the created file.
5.  The web shell executes commands on the Exchange server, allowing the attacker to gather information, move laterally within the network, or establish persistence.
6.  The attacker gains control over the Exchange server, potentially compromising sensitive data and services.
7.  The attacker may use the compromised Exchange server to access other systems within the network, expanding their reach.

## Impact

Compromised Microsoft Exchange servers can lead to the exposure of sensitive email communications, user credentials, and confidential business data. Successful exploitation and web shell deployment can grant attackers persistent access to the internal network, enabling lateral movement to other critical systems. The potential consequences include data theft, ransomware deployment, disruption of email services, and reputational damage. While the number of directly affected organizations is not specified in this brief, the broad adoption of Microsoft Exchange makes this a widespread concern.

## Recommendation

*   Deploy the Sigma rule "Microsoft Exchange Server UM Writing Suspicious Files" to your SIEM and tune for your environment to detect web shell creation (see below).
*   Prioritize patching CVE-2021-26858 on all internet-facing Exchange servers immediately to prevent initial exploitation.
*   Investigate any alerts generated by the Sigma rule, comparing suspicious file creations against established Microsoft baselines (see References).
*   Enable Sysmon file creation logging with the appropriate event ID to ensure adequate telemetry for the Sigma rules to function.
*   Consult Microsoft's Exchange support repository for additional tools and guidance on detecting and mitigating Exchange vulnerabilities (see References).
