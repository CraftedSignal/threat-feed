---
title: 'New Abuse of the ClickOnce Technology: Part 1'
slug: 2026-07-clickonce-abuse
description: Threat actors are newly abusing Microsoft's ClickOnce technology, intended for simplified application deployment and updates, to distribute malware by leveraging its user-friendly features that bypass traditional security controls, potentially leading to unauthorized execution and persistence on user endpoints.
date: "2026-07-05T07:43:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - clickonce
  - deployment
  - malware-distribution
  - defense-evasion
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
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: ClickOnce's user-friendly deployment process is a double-edged sword — while it simplifies software deployment for legitimate developers, it also provides threat actors with an easy way of spreading malware.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has identified a new method of abusing Microsoft's ClickOnce technology, a deployment mechanism designed for simplified application distribution and updates without administrative privileges. This initial brief, "Part 1," focuses on the technical inner workings of ClickOnce, explaining its deployment journey from developer publishing to user installation. Threat actors are exploiting ClickOnce's user-friendly features, such as minimal user interaction and automatic updates, to bypass traditional security controls and facilitate the stealthy distribution and execution of malicious software. This novel approach allows for applications to be run and optionally installed with little friction for the user, making it an attractive vector for malware delivery. Understanding this technology is crucial for defenders to anticipate and mitigate future attacks detailed in subsequent parts of this series.

## Impact

The abuse of ClickOnce technology poses a significant threat by enabling adversaries to distribute malware with minimal user interaction and without requiring elevated administrative privileges. This effectively circumvents common security measures that rely on user consent for administrative actions or block known malicious executables. If exploited, attackers can achieve initial access, establish persistence through ClickOnce's self-updating functionality, and execute arbitrary code on user endpoints, leading to data exfiltration, further compromise, or deployment of ransomware. The user-friendly design, intended for legitimate software, becomes a powerful tool for attackers to achieve covert deployment and continuous presence.

## Recommendation

* Review existing ClickOnce application deployments within your environment to understand their origins and update mechanisms.
* Monitor for unexpected or unsigned ClickOnce deployments, as these are potential indicators of malicious activity.
* Implement application whitelisting policies to restrict execution of unauthorized ClickOnce applications.
