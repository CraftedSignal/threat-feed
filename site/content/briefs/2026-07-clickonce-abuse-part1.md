---
title: 'New Abuse of ClickOnce Technology, Part 1: The Inner Workings of Application Deployment Abuse'
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are leveraging Microsoft's legitimate ClickOnce application deployment technology to distribute malware, taking advantage of its minimal user interaction and lack of elevated privilege requirements for installation.
date: "2026-07-07T16:20:57Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - microsoft
  - deployment
  - application-deployment
  - malware
  - initial-access
  - execution
  - windows
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: 'ClickOnce’s user-friendly deployment process is a double-edged sword — while it simplifies software deployment for legitimate developers, it also provides threat actors with an easy way of spreading malware... The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application. These deployment files can be hosted on the vendor''s website, where they introduce their app alongside an “Install” button. When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.'
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has highlighted a new abuse trend where threat actors are weaponizing Microsoft's ClickOnce technology for malware distribution. ClickOnce, a legitimate deployment solution designed to simplify application installation and updates, allows developers to publish applications that users can run and install with minimal interaction, often without requiring administrative privileges. This user-friendly design, however, presents a significant security risk as it enables threat actors to bypass traditional security controls. The technology's self-contained packaging and self-updating functionalities can be exploited to deliver and maintain malicious payloads discreetly. This brief, part one of a series, details the internal mechanisms of ClickOnce application deployment, setting the stage for understanding how these features can be subverted for malicious purposes.

## Impact

The abuse of ClickOnce technology enables threat actors to circumvent common security barriers, leading to widespread malware distribution and successful initial compromise. Because ClickOnce applications often install without requiring elevated privileges, they can bypass User Account Control (UAC) prompts, making it easier for users to unwittingly execute malicious software. The self-updating feature also provides a mechanism for persistence and payload evolution, allowing attackers to update their malware over time. This could result in unauthorized access, data exfiltration, system compromise, and the deployment of ransomware or other destructive payloads across targeted organizations.

## Recommendation

This brief details the mechanics of ClickOnce technology and its potential for abuse; specific detection strategies and examples of malicious exploitation will be covered in part two of the CrowdStrike series. Therefore, concrete detection engineering recommendations will be provided in a subsequent brief.
