---
title: New Abuse of Microsoft ClickOnce Technology for Malware Distribution
slug: 2026-06-clickonce-abuse
description: CrowdStrike researchers have detailed the internal mechanisms of Microsoft's ClickOnce technology, highlighting how its user-friendly, privilege-free application deployment can be abused by threat actors for distributing malware and bypassing traditional security controls.
date: "2026-06-19T05:10:40Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - deployment
  - malware
  - windows
  - initial-access
  - user-execution
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
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
rules:
  - title: Detect ClickOnce Deployment Service Execution
    description: Detects the execution of dfsvc.exe, the ClickOnce Deployment Support Service, which is central to ClickOnce application deployment. Investigate executions not initiated by trusted installers or browsers.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Application File Creation in User Directories
    description: Detects the creation of .application files, which are ClickOnce deployment manifests, in common user-writable or temporary directories, potentially indicating a malicious deployment attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1204.001
      - T1566.001
    data_sources:
      - file_event
      - windows
  - title: Detect Suspicious dfsvc.exe Network Connections
    description: Detects outbound network connections initiated by dfsvc.exe to suspicious or non-standard ports, which could indicate C2 communication or exfiltration from a malicious ClickOnce application.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

CrowdStrike has published an analysis detailing the inner workings of Microsoft's ClickOnce technology, a deployment mechanism designed to simplify application distribution and updates without requiring administrative privileges. While intended for legitimate software, ClickOnce's features—such as minimal user interaction for installation and self-updating capabilities—present a significant opportunity for abuse by threat actors. This report, Part 1 of a series, meticulously breaks down the publishing and deployment journey of ClickOnce applications, from creation using Visual Studio to their execution on an endpoint. This documentation underscores how the technology's inherent design, which prioritizes ease of use, can inadvertently serve as a streamlined vector for malware delivery, bypassing conventional security checks that rely on elevated permissions for software installation. Defenders need to understand these mechanics to detect and prevent malicious ClickOnce deployments.

## Attack Chain

1.  An attacker authors a malicious application and packages it using Microsoft's ClickOnce technology, specifying deployment parameters via Visual Studio's publish wizard.
2.  The attacker hosts the generated ClickOnce deployment files (e.g., `.application` manifests and associated binaries) on a controlled web server or network share.
3.  The attacker crafts a social engineering lure (e.g., phishing email, malicious website) to entice a victim into clicking a link that points to the hosted `.application` file.
4.  Upon clicking the link, the victim's operating system downloads the `.application` file, and the ClickOnce Deployment Support Service (`dfsvc.exe`) automatically initiates the deployment process.
5.  If the publisher's signature cannot be verified, the Windows operating system presents a user confirmation prompt, asking the victim to authorize the application deployment.
6.  Should the victim approve the prompt, the ClickOnce application is deployed and executed on the system without requiring elevated administrative privileges.
7.  The malicious ClickOnce application executes within the user's context, leveraging the simplified deployment mechanism to establish persistence or perform initial compromise actions.
8.  The deployed malicious application then proceeds with its intended objective, such as downloading additional payloads, exfiltrating data, or establishing command and control.

## Impact

Successful exploitation of ClickOnce technology for malicious purposes can lead to widespread and stealthy malware infections across an organization. Since ClickOnce applications install without administrative privileges, they can circumvent traditional endpoint security measures that focus on blocking privileged installations. The user-friendly "click-once" nature simplifies the attacker's delivery mechanism, potentially increasing victim success rates. This method allows threat actors to easily distribute various forms of malware, including info-stealers, ransomware, or backdoors, leading to data exfiltration, system compromise, and significant financial and reputational damage. The self-updating feature also allows threat actors to maintain persistence and evolve their payloads over time.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect suspicious ClickOnce activity.
*   Monitor `process_creation` events for `dfsvc.exe` and investigate executions originating from untrusted web browsers or unusual parent processes.
*   Enable `file_event` logging for `.application` and `.manifest` file creations, particularly in user-writable directories like `AppData\Local\Apps` or `Downloads`, to identify potentially malicious ClickOnce deployments.
*   Implement application control policies to restrict the execution of unsigned or untrusted ClickOnce applications, focusing on the origins and publishers of deployed applications.
*   Educate users about the risks of clicking on links from untrusted sources and the importance of verifying software publisher legitimacy before approving application installations.
