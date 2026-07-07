---
title: 'New Abuse of ClickOnce Technology: Part 1 - Understanding the Mechanism'
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are leveraging Microsoft's ClickOnce technology, a legitimate application deployment mechanism, to simplify malware distribution and execution, bypassing traditional administrative privilege requirements by tricking users into 'one-click' installations.
date: "2026-07-04T08:53:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - windows
  - microsoft
  - persistence
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
    evidence: developers can share one of the ClickOnce deployment files, on which the user would only have to 'click once' to deploy the application. These deployment files can be hosted on the vendor's website, where they introduce their app alongside an 'Install' button.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to ''click once'' to deploy the application.'
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

This brief, based on CrowdStrike's research, details the inner workings of Microsoft's ClickOnce technology, a legitimate application deployment framework that threat actors are exploiting to spread malware. ClickOnce enables developers to publish applications that users can run and install with minimal interaction and without requiring administrative privileges, presenting a "double-edged sword" for security. While it streamlines software distribution for legitimate purposes, its user-friendly, "one-click" deployment process makes it an attractive vector for malicious actors. The research, published on June 18, 2026, focuses on explaining how ClickOnce functions from application publication to endpoint installation, setting the stage for subsequent analysis of its weaponization by attackers. This allows for simplified initial access and execution on user endpoints, potentially bypassing traditional security controls.

## Attack Chain

This brief details the legitimate functionality of ClickOnce, which is a foundational mechanism for future abuse. A specific malicious attack chain is not described in this first part of the research.

## Impact

The abuse of ClickOnce technology allows threat actors to simplify malware delivery and execution on target systems. By leveraging the inherent trust in legitimate application deployment mechanisms, attackers can trick users into installing malicious applications with minimal interaction, often without needing administrative privileges. This can lead to initial access for attackers, bypassing common security layers, and facilitating further compromise, data exfiltration, or ransomware deployment if a malicious ClickOnce application is successfully deployed and executed. The ease of deployment and potential for widespread targeting makes this a significant concern for organizations.

## Recommendation

*   Enhance logging for process creation and file events related to ClickOnce components (e.g., `.application` files) as described in this brief.
*   Educate users about the risks associated with installing software from untrusted sources, even those appearing to use "one-click" installation methods, as ClickOnce deployment files are referenced in this brief.
*   Monitor for the execution of `.application` files and associated processes, which are key artifacts of ClickOnce technology described in this brief, especially when initiated from web browsers or email attachments.
