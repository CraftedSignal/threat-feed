---
title: 'New Abuse of the ClickOnce Technology, Part 1: The Inner Workings of ClickOnce Application Deployment'
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are abusing Microsoft's ClickOnce technology to spread malware, leveraging its streamlined application deployment process, which requires minimal user interaction and no elevated privileges, for initial access and persistence on Windows systems.
date: "2026-07-04T07:23:47Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - microsoft
  - deployment
  - malware-delivery
  - windows
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
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application.'
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has identified a new method for threat actors to abuse Microsoft's ClickOnce technology for malware distribution. ClickOnce is a legitimate deployment mechanism designed to streamline application installation and updates for .NET applications without requiring administrative privileges, offering a user-friendly "click-once" experience. This ease of deployment, however, makes it an attractive vector for malicious actors. By packaging malware as ClickOnce applications, attackers can bypass traditional security controls and leverage the technology's self-contained packaging and self-updating features for persistence and dynamic payload delivery. This brief, Part 1 of a series, details the internal workings of ClickOnce, explaining its deployment journey from developer publishing to user installation, laying the groundwork for understanding its security implications and potential weaponization in subsequent analyses.

## Attack Chain

1.  Attacker hosts a malicious ClickOnce application, packaging malware into ClickOnce-compatible resources.
2.  The malicious ClickOnce application's deployment files are hosted on an attacker-controlled website, often presented with an "Install" button.
3.  A user, tricked by social engineering or unaware of the risk, clicks the "Install" button on the webpage, triggering the download of the ClickOnce deployment file (`.application` manifest).
4.  The operating system (OS) initiates the deployment process and asks for the user’s confirmation, especially if the publisher’s signature cannot be verified.
5.  Upon the user's confirmation in the deployment wizard, the malicious ClickOnce application is deployed onto the system without requiring elevated administrative privileges.
6.  The deployed malicious application executes on the victim's machine, establishing initial access and executing its payload.
7.  The application can leverage ClickOnce's self-updating functionality to automatically fetch and install further malicious updates or components from the attacker's deployment server, maintaining persistence and command and control.

## Impact

The abuse of ClickOnce technology for malware distribution allows threat actors to bypass traditional security measures and install malicious applications with minimal user interaction and often without requiring elevated privileges. If successful, attackers can establish persistence, maintain command and control through the self-updating mechanism, and deploy various payloads, potentially leading to data exfiltration, system compromise, or ransomware deployment. The user-friendly nature of ClickOnce deployment also lowers the barrier for social engineering attacks, making it easier for users to unknowingly execute malicious code.

## Recommendation

*   Implement strong controls on the execution of `.application` files, specifically monitoring for their download and execution from untrusted or unexpected sources.
*   Configure process monitoring to alert on new application deployments that occur without elevated privileges, as ClickOnce is designed to function this way.
*   Educate end-users about verifying the publisher of any ClickOnce application before confirming its installation via the deployment wizard described in this brief.
