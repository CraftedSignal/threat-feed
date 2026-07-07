---
title: 'New Abuse of the ClickOnce Technology, Part 1: The Inner Workings of ClickOnce Application Deployment'
slug: 2026-07-clickonce-abuse-part1
description: CrowdStrike details how Microsoft's ClickOnce technology, designed for simplified application deployment and updates on Windows without requiring elevated privileges, presents a security risk as threat actors can abuse its user-friendly deployment process to distribute malware and facilitate attacks, leveraging its ability to execute and install with minimal user interaction.
date: "2026-07-07T14:36:05Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - windows
  - deployment
  - malware-delivery
  - threat-intelligence
vendors:
  - Microsoft
products:
  - ClickOnce technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: Minimal user interaction to deploy an application, hence the name 'ClickOnce,' highlighting that the deployment can be as simple as clicking a webpage 'Install' button in certain deployment scenarios
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The 'deployment' refers to the execution of a ClickOnce application and its potential installation onto the system afterward
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: No elevated privileges required to perform the deployment
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike's analysis, presented in this first part of a two-part series, details the internal workings of Microsoft's ClickOnce technology. Designed for simplified application deployment, ClickOnce allows developers to distribute applications that users can install and update with minimal interaction and without requiring elevated administrative privileges. While intended to ease software distribution, this user-friendly process presents a significant security risk as threat actors can readily abuse it to deploy malware. This brief examines how ClickOnce applications are published, deployed, and installed on user endpoints, emphasizing its core features like self-contained packaging and automatic updates. The research highlights that the technology's inherent design, particularly its ability to execute and install software via a single 'click,' makes it an attractive vector for malicious purposes, setting the stage for future discussions on observed weaponization and detection strategies.

## Impact

The potential for abuse of ClickOnce technology means that organizations are vulnerable to malware distribution campaigns that bypass traditional privilege requirements. If an attacker successfully leverages ClickOnce, they can achieve persistent execution of malicious code, potentially leading to data exfiltration, system compromise, or further network intrusion. The ease of deployment with minimal user interaction increases the likelihood of successful social engineering attacks, making it a valuable tool for threat actors aiming to establish initial access and maintain presence within targeted environments. While this part does not detail specific campaigns or victim counts, the inherent risks are high due to the technology's design.

## Recommendation

- Ensure `file_event` logging is enabled to monitor for the creation and modification of `.application` files, which serve as ClickOnce deployment manifests.
- Ensure `process_creation` logging is enabled to monitor for processes initiated by ClickOnce deployments, particularly the `dfsvc.exe` service, to identify unusual application installations.
