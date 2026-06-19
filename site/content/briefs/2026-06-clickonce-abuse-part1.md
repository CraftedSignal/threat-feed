---
title: Abuse of ClickOnce Technology for Malware Distribution
slug: 2026-06-clickonce-abuse-part1
description: CrowdStrike has identified a new abuse vector for Microsoft's ClickOnce technology, enabling threat actors to distribute malware with minimal user interaction and no administrative privileges by leveraging its streamlined application deployment features.
date: "2026-06-19T05:19:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - malware-distribution
  - initial-access
  - windows-security
  - deployment-technology
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
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
rules:
  - title: Detect ClickOnce Application Execution from Cache Directory
    description: Detects the execution of any process originating from the ClickOnce application cache directory, typically indicating a deployed ClickOnce application. This can be used to identify legitimate or malicious ClickOnce activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious ClickOnce Deployment Service Execution
    description: Detects execution of the ClickOnce Deployment Service (dfsvc.exe) with command line parameters indicating a remote or potentially malicious source. This can highlight attempts to deploy applications from untrusted locations.
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
  - title: Detect Download of ClickOnce Deployment Files from Browsers
    description: Detects the creation of ClickOnce deployment files (.application or .manifest) by common web browsers, which can indicate a user downloading a ClickOnce application, potentially malicious.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - file_event
      - windows
rules_count: 3
---

Microsoft's ClickOnce technology, designed for user-friendly application deployment and updates without requiring administrative privileges, has been identified as a new potential vector for malware distribution by threat actors. Published on June 18, 2026, by CrowdStrike, this initial part of a two-part series details the legitimate inner workings of ClickOnce, from application publishing in Visual Studio to its deployment on user endpoints. While intended to simplify software distribution, its features like minimal user interaction, self-contained packaging, and self-updating functionality present a double-edged sword, making it an attractive mechanism for attackers to bypass traditional security controls and spread malicious applications. This brief outlines the technical process and highlights why defenders need to understand this technology to prevent its misuse.

## Attack Chain

1.  **Craft Malicious ClickOnce Application**: Threat actor develops or packages a malicious payload (e.g., infostealer, ransomware) as a ClickOnce application using tools like Visual Studio, configuring it for web deployment and potential offline installation.
2.  **Host Deployment Files**: The malicious ClickOnce application's deployment manifest (`.application` file) and associated files are hosted on an attacker-controlled web server.
3.  **Distribution via Social Engineering**: The attacker distributes a link to the malicious `.application` file (e.g., via phishing emails, malicious advertisements, or compromised websites) to entice targets into initiating the deployment.
4.  **User Initiates Deployment**: The user clicks the provided link or directly executes the `.application` file, triggering the ClickOnce Deployment Services (`dfsvc.exe`) on their system.
5.  **Bypass Security Warning**: If the application is unsigned or from an untrusted publisher, the operating system presents a security prompt. The user, often due to social engineering, accepts the prompt, allowing deployment to proceed.
6.  **Execute Malicious Payload**: ClickOnce downloads and executes the malicious application from the attacker's server into the user's `AppData\Local\Apps\2.0\` directory, often without requiring administrative privileges.
7.  **Establish Persistence**: The malicious application may leverage ClickOnce's ability to "install" the application for offline use and its self-updating functionality to maintain persistence and retrieve new payloads.
8.  **Achieve Objective**: The executed malware performs its intended malicious actions, such as data exfiltration, system compromise, or ransomware deployment.

## Impact

While this brief focuses on the technical underpinnings rather than specific campaigns, the abuse of ClickOnce technology can lead to widespread malware infections, enabling various forms of cybercrime and espionage. The ease of deployment without administrative privileges and the user-friendly interface can trick users into installing malicious software, potentially compromising sensitive data, intellectual property, and financial resources. Organizations could face significant operational disruption, data breaches, and reputational damage if their users fall victim to ClickOnce-delivered malware. Specific victim counts or sectors are not detailed in this initial analysis.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce activity.
*   Monitor `process_creation` events for `dfsvc.exe` creating child processes from unusual paths (referencing `rule_clickonce_app_execution_cache`).
*   Implement network monitoring to detect downloads of `.application` and `.manifest` files from untrusted or unapproved domains (referencing `rule_clickonce_deployment_file_download`).
*   Ensure user awareness training covers the risks associated with clicking links from unknown sources, especially those leading to executable downloads or application installations.
