---
title: New Abuse of Microsoft ClickOnce Technology for Malware Deployment
slug: 2026-06-clickonce-abuse
description: Threat actors are abusing Microsoft's legitimate ClickOnce deployment technology to facilitate malware delivery and execution on Windows systems by leveraging its minimal user interaction and lack of administrative privilege requirements for application installation.
date: "2026-06-20T05:40:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - deployment
  - malware
  - clickonce
  - initial-access
  - execution
vendors:
  - Microsoft
products:
  - ClickOnce Technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
rules:
  - title: Detect ClickOnce Service Executing Suspicious Child Process
    description: Detects the ClickOnce deployment service (dfsvc.exe) initiating a child process that is often associated with malicious activities, indicating potential abuse of ClickOnce for malware delivery.
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
  - title: Detect ClickOnce Application Execution from Cache Directory
    description: Detects the execution of any process directly from the ClickOnce application cache directory, which is a common location for malicious ClickOnce applications after deployment.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Deployment File Download
    description: Detects the download of ClickOnce deployment files (.application or .appref-ms) which can be precursors to malicious ClickOnce attacks. This requires monitoring file creation/downloads by web browsers.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1204
    data_sources:
      - file_event
      - windows
rules_count: 3
---

CrowdStrike has identified a new abuse vector leveraging Microsoft's ClickOnce deployment technology for malware distribution. ClickOnce, designed to simplify application installation and updates, allows applications to be deployed with minimal user interaction and without requiring administrative privileges, making it an attractive target for adversaries. While the published article primarily details the internal workings of ClickOnce, it highlights how its user-friendly features—such as single-click deployment from web links, self-contained packaging, and self-updating capabilities—create a "double-edged sword." Attackers can weaponize this legitimate mechanism to deliver and execute malicious payloads, potentially establishing persistence through the self-updating functionality, impacting Windows users who are lured into deploying these compromised applications.

## Attack Chain

1.  **Initial Access / Lure:** The attacker publishes a malicious application using ClickOnce technology and hosts its deployment files (e.g., `.application` or `.appref-ms` files) on a controlled server or phishing site.
2.  **User Execution:** A victim is enticed to click a link (e.g., via email, malicious ad, or compromised website) that points to the attacker-controlled ClickOnce deployment file.
3.  **Deployment File Download:** Upon clicking, the victim's browser initiates the download of the ClickOnce deployment file (e.g., `malware.application` or `malware.appref-ms`).
4.  **ClickOnce Service Activation:** The operating system, recognizing the ClickOnce file extension, invokes the `dfsvc.exe` (ClickOnce Application Deployment Support Service) to handle the deployment.
5.  **User Confirmation:** If the application's publisher signature cannot be verified (which is likely for a malicious app), the OS prompts the user for confirmation to proceed with the deployment.
6.  **Malicious Application Deployment & Execution:** If the user approves, `dfsvc.exe` deploys the malicious application into the user's local ClickOnce cache (typically `C:\Users\<user>\AppData\Local\Apps\2.0\`) and immediately executes it.
7.  **Impact / Persistence:** The malicious application then performs its intended actions (e.g., payload execution, data exfiltration, C2 communication). It may also leverage ClickOnce's self-updating feature to maintain persistence or update its payload.

## Impact

The abuse of ClickOnce technology for malware distribution poses a significant risk as it bypasses common security barriers by leveraging a legitimate Microsoft deployment mechanism. Successful attacks can lead to full system compromise, data exfiltration, ransomware deployment, or integration into botnets. Because ClickOnce deployments often don't require administrative privileges, standard user accounts are sufficient for attackers to gain a foothold, increasing the attack surface. While specific victim counts or sectors are not detailed in this initial brief, any organization utilizing Windows environments is potentially exposed to this method of initial access and execution.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce activity.
*   Educate users on the risks of executing applications from untrusted sources, especially when prompted for confirmation by `dfsvc.exe` or `application` files.
*   Monitor `process_creation` events for `dfsvc.exe` spawning unusual child processes or initiating network connections to unapproved external domains.
*   Monitor `file_event` logs for the creation of `.application` or `.appref-ms` files in unexpected user directories or network shares.
*   Implement application control policies to restrict execution of unsigned ClickOnce applications or those from untrusted publishers.
