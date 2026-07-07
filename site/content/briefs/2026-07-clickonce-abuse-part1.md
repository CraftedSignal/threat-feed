---
title: New Abuse of ClickOnce Technology, Part 1
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are increasingly abusing Microsoft's legitimate ClickOnce application deployment technology to spread malware, leveraging its user-friendly 'click once' installation, self-contained packaging, and automatic update features to bypass traditional security controls and deploy malicious payloads without administrative privileges.
date: "2026-07-07T07:44:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - microsoft
  - application-deployment
  - malware-delivery
  - legitimate-feature-abuse
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce technology
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to ''click once'' to deploy the application. These deployment files can be hosted on the vendor''s website, where they introduce their app alongside an ''Install'' button. When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.'
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1072
    technique_name: Software Deployment Tools
    evidence: ClickOnce's user-friendly deployment process is a double-edged sword — while it simplifies software deployment for legitimate developers, it also provides threat actors with an easy way of spreading malware.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has highlighted a new method of abusing Microsoft's ClickOnce technology, a legitimate deployment mechanism designed for streamlined application distribution and updates without requiring administrative privileges. While intended to simplify software installation for users, its "click once" deployment model, self-contained packaging, and automatic update capabilities present an attractive vector for threat actors. This initial part of a two-part series details the internal workings of ClickOnce, including the publishing process from Visual Studio, the generation of deployment manifests (.application files), and the user-friendly installation wizard. Understanding these legitimate functions is crucial for defenders to anticipate the weaponization methods that will be discussed in subsequent research, as adversaries leverage these features to easily deliver and maintain persistent malware on victim systems.

## Impact

If successfully abused, ClickOnce technology can facilitate the widespread deployment of malware and unauthorized applications across targeted organizations. Its design, which bypasses traditional installation hurdles by not requiring elevated privileges and offering seamless updates, means that malicious payloads could be delivered with minimal user friction and evade certain security controls. This ease of deployment can lead to rapid infection rates, enabling data exfiltration, ransomware deployment, or establishing long-term persistence within an enterprise network, potentially affecting numerous users and systems without immediate detection.

## Recommendation

*   Review the technical details of ClickOnce application deployment as described in this brief to understand its legitimate operational mechanisms.
*   Anticipate that the insights and detection strategies for malicious ClickOnce abuse will be provided in Part 2 of this CrowdStrike series, and prioritize their implementation upon release.
