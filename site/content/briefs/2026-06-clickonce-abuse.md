---
title: Threat Actors Abuse Microsoft ClickOnce Technology for Malware Distribution
slug: 2026-06-clickonce-abuse
description: Threat actors are actively leveraging Microsoft's ClickOnce technology, a legitimate application deployment mechanism, to distribute and execute malware by exploiting its user-friendly deployment process that bypasses administrative privilege requirements.
date: "2026-06-20T09:11:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware
  - distribution
  - windows
  - deployment
  - endpoint
vendors:
  - Microsoft
products:
  - ClickOnce technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
rules:
  - title: Detect ClickOnce Deployment Service Execution
    description: Detects the execution of dfsvc.exe, the ClickOnce Deployment Services process, which is responsible for deploying ClickOnce applications. This can indicate legitimate activity or the initiation of a malicious ClickOnce application.
    platform: sigma
    severity: low
    tactics:
      - execution
    techniques:
      - T1204.001
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Rundll32 Launching ClickOnce Shim
    description: Detects rundll32.exe being used to launch the ClickOnce shim (dfshim.dll), a common method for initiating ClickOnce application installations or executions. This is a legitimate mechanism that can be abused by threat actors.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.001
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious ClickOnce Shortcut Creation
    description: Detects the creation of '.appref-ms' files, which are shortcuts for installed ClickOnce applications. Monitoring their creation, especially in unusual paths or by unexpected processes, can indicate malicious ClickOnce deployment.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 3
---

CrowdStrike has identified a growing trend where threat actors are weaponizing Microsoft's ClickOnce technology to simplify malware distribution and execution. ClickOnce, designed to ease application deployment and updates without requiring administrative privileges, presents a double-edged sword: while beneficial for legitimate developers, its "click-once" installation model is being co-opted by adversaries. This report, "New Abuse of the ClickOnce Technology, Part 1", delves into the fundamental mechanics of ClickOnce, detailing how applications are published, deployed, and installed on user endpoints. The inherent trust model and low friction associated with ClickOnce make it an attractive vector for threat actors seeking to bypass traditional security controls and deploy malicious payloads with minimal user interaction. Defenders need to understand these internal workings to effectively detect and mitigate such abuses, as the technology streamlines the path from initial access to execution for malicious software.

## Attack Chain

1.  **Crafting Malicious Application**: An attacker publishes a malicious application using ClickOnce technology, generating `.application` and `.manifest` files, along with the associated binaries.
2.  **Initial Access / Delivery**: The attacker hosts the malicious ClickOnce deployment files (e.g., `.application` file) on a controlled web server or distributes them via phishing emails, tricking users into initiating the download.
3.  **User Execution**: The victim navigates to the malicious URL or clicks a link, triggering the download of the `.application` deployment file, which the Windows operating system then attempts to process.
4.  **Deployment Initiation**: Upon execution of the `.application` file, the ClickOnce deployment service (`dfsvc.exe` or `rundll32.exe` interacting with `dfshim.dll`) initiates the application deployment process on the user's system.
5.  **User Confirmation Prompt**: The operating system presents a user confirmation prompt, particularly if the publisher's signature cannot be verified or is unknown, requiring the user to explicitly approve the application's deployment.
6.  **Application Deployment & Execution**: If the user approves, the ClickOnce application is deployed (either executed as a temporary application or installed), potentially creating an `.appref-ms` shortcut, and the malicious payload within begins its intended activities.
7.  **Persistence (Optional)**: If configured by the attacker, the ClickOnce application can be installed and leverage its self-updating functionality to maintain persistence and fetch additional malicious components from the attacker's server.
8.  **Impact**: The malicious ClickOnce application executes its payload, leading to outcomes such as malware installation, data exfiltration, or further compromise of the victim's system.

## Impact

The abuse of ClickOnce technology directly facilitates the widespread distribution of malware, posing a significant risk to organizations across all sectors. Its design allows for application deployment without requiring elevated administrative privileges, meaning even standard users can inadvertently install malicious software, bypassing critical security layers. If successful, such attacks can lead to system compromise, data breaches, ransomware deployment, and lateral movement within the compromised network. While the specific number of victims or targeted sectors is not detailed in this initial report, the broad applicability of ClickOnce as a delivery mechanism suggests a wide scope of potential targeting, impacting any organization where users can initiate ClickOnce deployments.

## Recommendation

*   Enable verbose process creation logging (e.g., Sysmon Event ID 1) to capture executions of `dfsvc.exe` and `rundll32.exe` for analysis of potential ClickOnce abuse.
*   Deploy the Sigma rules provided in this brief to your SIEM solution to detect suspicious ClickOnce application deployments and tune them for your environment.
*   Educate users about the risks of installing software from untrusted sources, even if it appears to be a legitimate ClickOnce application.
*   Monitor for the creation of `.appref-ms` files in unusual directories or by unexpected parent processes, as highlighted in the `Detect Suspicious ClickOnce Shortcut Creation` rule.
*   Implement application whitelisting solutions to restrict the execution of unsigned or untrusted ClickOnce applications.
