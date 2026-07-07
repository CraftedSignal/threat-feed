---
title: Abuse of Microsoft ClickOnce Technology for Malware Distribution
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are increasingly abusing Microsoft's ClickOnce technology, which allows user-friendly, low-privilege application deployment, to distribute malware by tricking users into executing malicious applications, thereby achieving initial access and potentially persistence on target systems.
date: "2026-07-07T12:45:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-distribution
  - application-deployment
  - windows-security
  - initial-access
  - execution
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Users can be tricked into deploying malicious ClickOnce applications through a simple 'click once' mechanism.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The OS asks for the user’s confirmation if the publisher’s signature cannot be verified, and upon confirmation, uses a standardized procedure to deploy the app.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Whether or not the application should be available offline, which determines if the application should only be executed, or also installed into the system
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

Adversaries are leveraging Microsoft's ClickOnce technology, a deployment framework designed for easy application distribution and installation, as a vector for malware delivery. This method exploits ClickOnce's core features, such as minimal user interaction, no elevated privilege requirements, and self-updating capabilities, making it an attractive pathway for initial access. The technology allows developers to package and export software into ClickOnce-compatible resources, which can then be hosted on websites or network shares. When a user clicks an "Install" button or a ClickOnce deployment file (.application), the system initiates the application deployment, optionally installing it. If the application's publisher signature cannot be verified, the operating system prompts the user for confirmation, which malicious actors can exploit through social engineering to trick victims into running untrusted code. This approach bypasses traditional security measures by masquerading as legitimate software deployment, posing a significant threat for organizations as it facilitates the effortless spread of malicious payloads.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass common security controls and establish a foothold within victim environments. If successful, this can lead to the installation of various malware, including ransomware, information stealers, or remote access Trojans, resulting in data exfiltration, system compromise, or disruption of operations. The user-friendly nature of ClickOnce deployment means that even non-technical users can inadvertently facilitate an attack, expanding the attack surface. While this particular brief (Part 1) focuses on the technical underpinnings, the implications of such a widespread, low-friction deployment method being weaponized are substantial, potentially affecting a broad range of industries and individuals who rely on Windows-based systems.

## Recommendation

*   Educate users about the risks of deploying untrusted ClickOnce applications, especially those from unverified publishers or unexpected sources, reinforcing the importance of verifying publisher signatures before proceeding.
*   Implement endpoint detection and response (EDR) solutions capable of monitoring and alerting on ClickOnce application deployments, particularly focusing on applications with unverified publisher signatures as described in the brief.
*   Configure endpoint security policies to restrict or flag the execution of ClickOnce applications from untrusted sources, leveraging application control mechanisms.
