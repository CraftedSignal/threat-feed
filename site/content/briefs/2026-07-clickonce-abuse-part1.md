---
title: Abuse of ClickOnce Technology for Malware Distribution
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are actively abusing Microsoft's ClickOnce technology, a legitimate application deployment mechanism, to distribute and execute malware, simplifying software installation for users while providing an easy way of spreading malicious applications with minimal user interaction.
date: "2026-07-06T07:25:13Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - clickonce
  - malware-distribution
  - windows
  - application-deployment
vendors:
  - Microsoft
products:
  - ClickOnce technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: ClickOnce enables developers to package and distribute applications that users can run, install, and automatically update with minimal interaction and without requiring administrative privileges. ClickOnce's user-friendly deployment process is a double-edged sword — while it simplifies software deployment for legitimate developers, it also provides threat actors with an easy way of spreading malware.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
rules:
  - title: Detect ClickOnce Deployment Service Execution from Web Browser
    description: Detects the execution of the ClickOnce Deployment Framework Services (dfsvc.exe) process, typically involved in ClickOnce application deployments, when initiated as a child process of common web browsers. This activity can indicate a user-initiated application install via ClickOnce, which can be benign or malicious.
    platform: sigma
    severity: informational
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - process_creation
      - windows
  - title: Detect ClickOnce Deployment Shim (dfshim.dll) Execution from Web Browser
    description: Detects the execution of rundll32.exe with the dfshim.dll library, a common method for initiating ClickOnce application deployments, when launched as a child process of a web browser. This can be an indicator of a user-initiated ClickOnce install, which can be abused by threat actors.
    platform: sigma
    severity: informational
    tactics:
      - execution
    techniques:
      - T1204
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CrowdStrike has published a two-part series detailing the abuse of Microsoft's ClickOnce technology for malware distribution. Part 1, published on June 18, 2026, focuses on the inner workings of ClickOnce, a legitimate application deployment mechanism designed to simplify software installation and updates for Windows users. Threat actors are leveraging ClickOnce's user-friendly features, which include minimal user interaction and no requirement for administrative privileges, to easily spread malicious applications. The technology allows developers to package and distribute applications that can be installed with a single click, a process that attackers can co-opt to deliver malware. This means defenders must understand the legitimate deployment journey of ClickOnce applications to anticipate and detect malicious exploitation, which will be further elaborated in Part 2 of CrowdStrike's research.

## Attack Chain

1.  Attacker hosts a malicious ClickOnce deployment file (e.g., an `.application` or `.vsto` file) on a web server or file share.
2.  User navigates to a malicious website or is tricked into clicking a link to the hosted ClickOnce deployment file.
3.  The user clicks an "Install" button or direct link, triggering the download of the `.application` file.
4.  The operating system prompts the user for confirmation to install the application, especially if the publisher's signature cannot be verified.
5.  Upon user confirmation, the ClickOnce deployment process initiates, downloading the application's associated files (executables, DLLs, etc.). This often involves `dfsvc.exe` or `rundll32.exe` calling `dfshim.dll`.
6.  The malicious ClickOnce application executes its payload, potentially installing itself persistently on the system without requiring elevated administrative privileges.

## Impact

While Part 1 focuses on the underlying technology, the implication of ClickOnce abuse is the simplified distribution and execution of malware on Windows systems. Attackers can bypass traditional security hurdles like administrative privilege requirements, enabling a smoother infection process for end-users. The potential for widespread malware deployment via seemingly legitimate click-to-install mechanisms poses a significant risk for organizations, as it can lead to various outcomes from data exfiltration and ransomware to persistent access, without requiring sophisticated zero-day exploits or complex infection vectors.

## Recommendation

*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect ClickOnce application deployments initiated from web browsers.
*   Monitor `process_creation` logs for the execution of `dfsvc.exe` or `rundll32.exe` with `dfshim.dll` parameters, especially when initiated by web browsers, to identify potential ClickOnce activity.
