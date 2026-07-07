---
title: 'New Abuse of ClickOnce Technology, Part 1: Internal Workings and Potential for Misuse'
slug: 2026-07-clickonce-abuse-part-1
description: Microsoft's ClickOnce technology, designed for simplified application deployment and automatic updates without requiring administrative privileges, is being abused by threat actors through its user-friendly 'click once' installation process, making it an attractive vector for distributing malware, enabling initial access, execution, and potential persistence on Windows systems.
date: "2026-07-07T12:12:15Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - application-deployment
  - windows
  - legitimate-software-abuse
  - threat-intelligence
vendors:
  - Microsoft
products:
  - ClickOnce technology
  - ClickOnce applications
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to ''click once'' to deploy the application.'
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: it also provides threat actors with an easy way of spreading malware.
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

CrowdStrike has identified a new vector for abuse leveraging Microsoft's ClickOnce technology, a deployment framework designed to simplify application distribution and updates. While intended to provide a user-friendly way for developers to share software, allowing users to install applications with minimal interaction and without administrative privileges, this ease of use presents a significant opportunity for threat actors. This first part of a two-part series details the internal mechanisms of ClickOnce, explaining how applications are published and deployed. The underlying functionality, which includes self-contained packaging, automatic updates, and simplified installation, creates a pathway for malicious actors to spread malware, achieve initial access, execute arbitrary code, and establish persistence on Windows systems. This brief focuses on the legitimate workflow, setting the groundwork for understanding how adversaries can weaponize the technology.

## Impact

If abused, ClickOnce technology can become an effective mechanism for malware distribution, bypassing traditional security measures by leveraging a trusted Microsoft deployment framework. Successful exploitation could lead to initial access to victim systems, arbitrary code execution, and persistent presence, as applications installed via ClickOnce can be configured for offline availability and automatic updates. This facilitates long-term compromise and enables attackers to maintain control over compromised endpoints without requiring elevated privileges for the initial installation. The potential for widespread impact stems from ClickOnce's design to simplify software deployment across various user bases and environments.
