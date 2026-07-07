---
title: 'New Abuse of ClickOnce Technology, Part 1: Inner Workings of Application Deployment'
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are increasingly leveraging Microsoft's ClickOnce technology, a deployment mechanism designed to simplify application installation and updates, to distribute malware by exploiting its minimal user interaction and lack of administrative privilege requirements, with initial compromise often occurring through users clicking an 'Install' button on a webpage.
date: "2026-07-05T07:07:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - clickonce
  - malware-distribution
  - threat-actor-techniques
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
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: These deployment files can be hosted on the vendor's website, where they introduce their app alongside an “Install” button. When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.
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

Microsoft's ClickOnce technology, intended to simplify application distribution and updates, is being increasingly abused by threat actors as a potent mechanism for malware delivery. This deployment method allows developers to package and export software, enabling users to execute and optionally install applications with minimal interaction and without requiring administrative privileges. While ClickOnce streamlines legitimate software deployment, its user-friendly nature provides an attractive channel for adversaries to spread malicious payloads. The observed delivery mechanism typically involves tricking users into initiating the deployment by clicking an 'Install' button, which triggers the download and execution of a malicious ClickOnce application. This first part of a two-part series by CrowdStrike details the underlying mechanics of ClickOnce deployment, setting the stage for understanding how attackers exploit this functionality and why it poses a significant challenge for defenders given its legitimate system integration.

## Impact

The abuse of ClickOnce technology allows threat actors an "easy way of spreading malware" through a trusted Microsoft component. This circumvents traditional security measures that might flag suspicious executables requiring elevated privileges. If successful, this can lead to unauthorized code execution, installation of persistent malware, and potentially full system compromise. The simplicity of deployment and updating means that once a malicious ClickOnce application is established, it can easily update itself, maintaining persistence and evolving its capabilities without further user interaction, posing a sustained threat to victim organizations across various sectors.

## Recommendation

*   Educate users about the risks associated with installing software from untrusted sources, even if it appears to be a standard Windows installation wizard, as this is a primary initial access vector for ClickOnce abuse.
*   Implement application whitelisting solutions to prevent the execution of unauthorized ClickOnce applications, ensuring only approved software can run.
*   Enable comprehensive logging for ClickOnce-related processes (`dfsvc.exe`, `mscorsvw.exe`, `installutil.exe`, `regasm.exe`) to monitor for unusual activity, which will be critical for detecting abuse.
*   Monitor network traffic for connections initiated by ClickOnce applications (`.application` files) to unexpected or known malicious domains.
*   Subscribe to threat intelligence feeds (such as the upcoming Part 2 of this CrowdStrike series) that detail specific abuse patterns and associated IOCs to update detection capabilities.
