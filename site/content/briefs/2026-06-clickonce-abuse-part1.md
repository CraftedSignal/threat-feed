---
title: Abuse of Microsoft ClickOnce Technology for Malware Deployment
slug: 2026-06-clickonce-abuse-part1
description: Threat actors are leveraging Microsoft's ClickOnce technology, designed for simplified application deployment, as an attractive vector to spread malware, allowing for easy distribution, minimal user interaction, and installation without elevated privileges on Windows systems.
date: "2026-06-20T15:38:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - deployment
  - windows
  - malware-distribution
  - application-deployment
vendors:
  - Microsoft
products:
  - ClickOnce
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
  - title: Detect ClickOnce Deployment Service Launching Applications
    description: Detects the ClickOnce deployment service (dfsvc.exe) launching child processes, which can indicate the execution of a ClickOnce application. Focus on unusual child processes.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - process_creation
      - windows
  - title: Detect Download of Suspicious ClickOnce Deployment Files
    description: Detects the download of ClickOnce deployment files (.application, .manifest) which could indicate initial access attempts via user execution.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1204.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce Application Execution from Suspicious Paths
    description: Detects the execution of ClickOnce applications from common temporary or untrusted user-writable directories, which is indicative of malicious use.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - process_creation
      - windows
rules_count: 3
---

Microsoft's ClickOnce technology, intended to streamline application distribution and updates, is being increasingly abused by threat actors to deploy malicious software. ClickOnce facilitates the deployment of applications with minimal user interaction and often without requiring administrative privileges, making it an ideal vector for malware. This allows adversaries to package and distribute their payloads in a user-friendly format, potentially bypassing traditional security controls. While Part 1 of this research focuses on the internal workings of ClickOnce, it highlights features such as self-contained packaging and self-updating functionality which, if weaponized, could enable persistent and evasive malware campaigns. This abuse poses a significant risk to organizations, as it simplifies the initial access and execution phases for attackers by leveraging a legitimate Microsoft deployment mechanism.

## Attack Chain

1.  Threat actor packages a malicious application using Microsoft's ClickOnce publishing tools in Visual Studio.
2.  The actor hosts the generated ClickOnce deployment files (e.g., `.application` manifest, executable, `.deploy` files) on a remote web server or network share.
3.  The attacker creates a malicious link, often embedded in a phishing email or hosted on a compromised website, to trigger the download and deployment of the ClickOnce application.
4.  A user clicks the malicious link, which initiates the download of the `.application` deployment manifest.
5.  The Windows operating system's ClickOnce deployment service (`dfsvc.exe`) processes the manifest and, if the publisher's signature is not verified, prompts the user for confirmation.
6.  Upon user confirmation, `dfsvc.exe` downloads and executes the packaged malicious application.
7.  The malicious application runs with the user's privileges, potentially performing actions such as data exfiltration or installing additional malware.
8.  If configured for installation, the malicious ClickOnce application might establish persistence (e.g., via startup entries) and use ClickOnce's self-updating feature for dynamic command and control.

## Impact

The abuse of ClickOnce technology allows attackers to easily distribute malware, potentially leading to widespread infections. Because ClickOnce applications often run without requiring administrative privileges, they can bypass security measures that rely on privilege escalation detection. Successful exploitation can result in unauthorized access, data theft, further system compromise, and the deployment of ransomware or other destructive payloads. The self-updating nature of ClickOnce applications means that initially deployed malware can evolve, receive new capabilities, or evade detection over time, making long-term compromise more likely.

## Recommendation

*   Deploy the Sigma rule "Detect ClickOnce Deployment Service Launching Applications" to monitor `dfsvc.exe` activity for suspicious application launches.
*   Implement the Sigma rule "Detect Download of Suspicious ClickOnce Deployment Files" to identify `.application` or `.manifest` files downloaded from unusual sources.
*   Use the Sigma rule "Detect ClickOnce Application Execution from Suspicious Paths" to flag executions of ClickOnce apps from temporary or user-controlled directories.
*   Educate users on the risks associated with installing unsigned or untrusted applications via ClickOnce prompts.
*   Enable comprehensive process creation logging for `dfsvc.exe` to capture command-line arguments and parent-child process relationships.
