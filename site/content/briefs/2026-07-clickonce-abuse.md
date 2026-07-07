---
title: Threat Actors Exploiting Microsoft ClickOnce Technology for Malware Delivery
slug: 2026-07-clickonce-abuse
description: Threat actors are actively leveraging Microsoft's legitimate ClickOnce application deployment technology, which allows for minimal interaction application installation without administrative privileges, to distribute and execute malicious applications, thereby facilitating initial access, execution, and potential persistence on Windows systems.
date: "2026-07-07T14:43:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware
  - windows
  - application-deployment
  - execution
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
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to ''click once'' to deploy the application.'
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to ''click once'' to deploy the application.'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1072
    technique_name: Software Deployment Tools
    evidence: ClickOnce is a 'deployment technology,' which refers to the process of getting an application published with the ClickOnce technology to run and optionally install on a remote system.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1072
    technique_name: Software Deployment Tools
    evidence: No elevated privileges required to perform the deployment
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has highlighted the increasing abuse of Microsoft's ClickOnce technology by threat actors. ClickOnce is a legitimate Windows deployment mechanism designed to simplify application installation and updates for users, requiring minimal interaction and no administrative privileges. This user-friendly nature, however, makes it an attractive vector for adversaries to deliver malware. While this first part of a two-part series primarily details the technical inner workings of ClickOnce, it sets the stage for understanding how attackers can weaponize it to bypass traditional security controls and establish a foothold on victim systems. The technique allows attackers to deploy malicious applications that appear legitimate, leveraging a trusted Microsoft framework for their operations. This poses a significant challenge for defenders as it can enable initial access and execution of arbitrary code without triggering typical high-privilege alerts.

## Attack Chain

1.  **Craft Malicious ClickOnce Application**: An attacker develops a malicious application and packages it using the ClickOnce technology, generating the necessary deployment manifest (`.application` file) and associated files.
2.  **Host Deployment Files**: The attacker hosts the malicious ClickOnce deployment files on a controlled web server, network share, or other accessible medium.
3.  **Lure Victim to Initiate Deployment**: The victim is enticed (e.g., via phishing emails, malicious websites, or social engineering) to access the hosted deployment file, typically by clicking an "Install" button or directly opening the `.application` file.
4.  **User Execution Confirmation**: The operating system may present a security warning or prompt for user confirmation, which the attacker's social engineering attempts to bypass or trick the user into accepting.
5.  **ClickOnce Initiates Deployment**: Upon user confirmation, the ClickOnce deployment service (`dfsvc.exe` or equivalent) downloads and verifies the application manifest and associated files.
6.  **Application Execution**: The malicious ClickOnce application is deployed and executed on the victim's system, potentially without requiring administrative privileges, as per ClickOnce design.
7.  **Malware Payload Delivery/Execution**: The executed malicious application proceeds to carry out its intended objective, such as installing additional malware, establishing persistence, exfiltrating data, or launching ransomware.

## Impact

The abuse of ClickOnce technology poses a substantial risk, as it allows threat actors to bypass typical defenses by leveraging a legitimate, trusted application deployment mechanism. If successful, this attack vector can lead to unauthorized code execution, malware infection, data theft, and full system compromise, all initiated by minimal user interaction and often without requiring elevated privileges. While this brief does not detail specific victim counts or observed damage, the inherent design of ClickOnce facilitates widespread deployment, making a wide range of Windows users susceptible. The primary impact is the ease with which attackers can achieve initial access and execute payloads, increasing the likelihood of successful breaches across various sectors.

## Recommendation

*   Enable logging for process creation and command line activity to detect executions of `dfsvc.exe` and any subsequent child processes, which are key artifacts for observing ClickOnce deployments.
*   Monitor file creation events for `.application` and `.manifest` files, especially in user-specific or temporary directories, using file_event logging.
*   Implement application whitelisting policies to restrict the execution of unsigned or untrusted ClickOnce applications, going beyond default OS trust mechanisms.
*   Educate users on the risks associated with installing applications from untrusted sources, even when presented with seemingly legitimate Microsoft deployment prompts, as ClickOnce relies on user interaction.
