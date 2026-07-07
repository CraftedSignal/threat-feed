---
title: 'New Abuse of the ClickOnce Technology, Part 1: The Inner Workings of ClickOnce Application Deployment'
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are leveraging Microsoft's ClickOnce technology, a legitimate application deployment framework, to distribute malware, enabling applications to be installed and executed on user systems with minimal interaction and without requiring administrative privileges, thus serving as an effective method for initial access and execution of malicious code by tricking users into deploying a crafted application.
date: "2026-07-07T15:24:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - microsoft
  - deployment
  - malware
  - windows
  - initial-access
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
    evidence: developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application. These deployment files can be hosted on the vendor's website, where they introduce their app alongside an “Install” button.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: ClickOnce is a “deployment technology,” which refers to the process of getting an application published with the ClickOnce technology to run and optionally install on a remote system.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: ClickOnce's user-friendly deployment process is a double-edged sword — while it simplifies software deployment for legitimate developers, it also provides threat actors with an easy way of spreading malware.
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has identified a growing abuse of Microsoft's ClickOnce technology by threat actors for malware distribution. ClickOnce is a legitimate deployment framework designed to simplify application installation and updates for end-users, requiring minimal interaction and no administrative privileges. This user-friendly design, however, presents a significant security challenge, as attackers can weaponize it to deploy malicious applications. Part 1 of CrowdStrike's research delves into the technical internals of ClickOnce, detailing its publishing and deployment processes. It highlights how the technology's core features, such as self-contained packaging and self-updating capabilities, can be co-opted to establish initial access and execution on victim machines, making it a potent tool for bypassing traditional security controls and distributing payloads like infostealers or ransomware by convincing a user to "click once" on a malicious deployment link.

## Attack Chain

1.  A developer (or threat actor) uses Visual Studio to "publish" a C# or Visual Basic application, configuring deployment parameters for ClickOnce.
2.  The publishing process generates key ClickOnce resources, including a `.application` file (the deployment manifest).
3.  The attacker hosts the malicious ClickOnce deployment files (e.g., `.application` file) on a controlled web server or network share.
4.  The victim is socially engineered to visit the attacker's hosted location and click an "Install" button or directly presented with a malicious `.application` file.
5.  Upon clicking, the operating system prompts the user for confirmation regarding the application's publisher.
6.  If the user confirms, the ClickOnce deployment process initiates, downloading and deploying the application, potentially installing it onto the system without requiring elevated privileges.
7.  The malicious ClickOnce application executes, gaining initial foothold and establishing persistence or executing its payload.
8.  The application may leverage its self-updating functionality to fetch additional malicious components or maintain covert communication with attacker infrastructure for further command and control or data exfiltration.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass security measures and deploy malicious applications with ease, often without requiring administrative privileges. If successful, this can lead to initial access for attackers, enabling them to execute arbitrary code, establish persistence, exfiltrate sensitive data, or deploy ransomware. The user-friendly nature of ClickOnce means victims can inadvertently install sophisticated malware with a single click, making it a highly effective method for broad targeting across various sectors.

## Recommendation

*   Educate users about the risks associated with installing untrusted applications, even those presented through seemingly legitimate ClickOnce prompts.
*   Monitor process creation logs for `dfsvc.exe` (ClickOnce Application Deployment Support Service) starting unexpected or unsigned applications, which can indicate malicious ClickOnce activity.
*   Implement application whitelisting solutions to prevent the execution of unsigned or untrusted ClickOnce applications.
*   Enable comprehensive logging for file system events, particularly in user profile directories (`%USERPROFILE%`), to detect the creation of new application folders by ClickOnce outside of expected paths.
*   Deploy endpoint detection and response (EDR) solutions capable of monitoring and blocking execution of suspicious ClickOnce deployments.
