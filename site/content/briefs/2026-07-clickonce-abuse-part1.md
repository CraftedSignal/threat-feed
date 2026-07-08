---
title: Abuse of Microsoft ClickOnce Technology for Malware Distribution
slug: 2026-07-clickonce-abuse-part1
description: CrowdStrike details the inner workings of Microsoft's ClickOnce deployment technology, highlighting its user-friendly features, which, while beneficial for legitimate software distribution, create a significant opportunity for threat actors to easily spread malware to Windows systems without requiring administrative privileges, initiating deployment through simple user interaction.
date: "2026-07-08T06:09:09Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - deployment
  - malware-distribution
  - clickonce
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
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application. These deployment files can be hosted on the vendor''s website, where they introduce their app alongside an “Install” button. When clicked, the button triggers the download of the ClickOnce deployment file.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application.'
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has published the first part of a series detailing the new abuse of Microsoft's ClickOnce technology, a deployment mechanism designed to simplify application distribution and updates for developers and users. Released on June 18, 2026, this report, written by Mathilde Venault, primarily focuses on the technical internal workings of ClickOnce. The technology allows applications to be run, installed, and updated with minimal user interaction and without requiring elevated administrative privileges. While intended for legitimate software, this ease of deployment presents a significant security risk, as threat actors can weaponize ClickOnce to distribute malware. The article emphasizes that this dual-edged nature makes ClickOnce an attractive vector for adversaries seeking to bypass traditional installation hurdles, underscoring the need for defenders to understand its mechanics ahead of Part 2, which will cover specific weaponization methods and detection strategies.

## Attack Chain

1.  A developer (or threat actor) publishes a ClickOnce application using tools like Visual Studio, generating key deployment files such as the `.application` manifest.
2.  The `.application` manifest and associated files are hosted on a web server or network share, accessible to target users.
3.  A user is enticed to click an "Install" button or a link pointing to the `.application` file, typically on a webpage.
4.  Upon clicking, the operating system initiates the ClickOnce deployment process, which downloads the necessary application files.
5.  The OS prompts the user for confirmation if the publisher's signature cannot be verified, proceeding with deployment upon user consent.
6.  The ClickOnce application is executed and optionally installed on the user's system without requiring administrative privileges.
7.  The application, potentially malicious, runs on the endpoint, allowing initial access or further stages of an attack such as execution of arbitrary code or data exfiltration.

## Impact

The primary impact of ClickOnce technology's abuse is the silent and widespread distribution of malware to Windows endpoints. Because ClickOnce applications can be deployed without administrative privileges and with minimal user interaction, it significantly lowers the barrier for entry for threat actors. If an attacker successfully leverages this method, organizations could face widespread compromises, data breaches, and system infections, potentially leading to financial losses, reputational damage, and operational disruption. The ease with which users can inadvertently trigger these deployments means that even well-meaning users can become vectors for significant organizational compromise.

## Recommendation

*   Educate users about the risks associated with downloading and executing applications from untrusted sources, particularly those initiated by a "single click" or browser prompt.
*   Implement application whitelisting solutions to restrict the execution of unauthorized ClickOnce applications (e.g., unsigned or from unapproved publishers).
*   Enable comprehensive process creation and file event logging (e.g., via Sysmon) on all Windows endpoints to monitor for suspicious ClickOnce deployment activity, specifically targeting the creation or execution of `.application` and `.manifest` files outside of expected paths.
*   Monitor network traffic for connections initiated by newly deployed ClickOnce applications to unusual or unauthorized external IP addresses or domains.
*   Regularly review and update security policies to reflect the evolving threat landscape, including potential abuse of legitimate deployment technologies like ClickOnce.
