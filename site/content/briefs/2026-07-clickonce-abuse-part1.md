---
title: 'New Abuse of ClickOnce Technology, Part 1: Understanding Deployment for Malware Spread'
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are identified as abusing Microsoft's legitimate ClickOnce application deployment technology, which simplifies software distribution and updates without administrative privileges, to spread malware, leveraging its trusted nature for initial access, execution, and defense evasion.
date: "2026-07-07T18:56:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - microsoft
  - legitimate-software-abuse
  - defense-evasion
  - initial-access
  - windows
  - deployment
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
    evidence: on which the user would only have to 'click once' to deploy the application. When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
    evidence: ClickOnce's user-friendly deployment process is a double-edged sword — while it simplifies software deployment for legitimate developers, it also provides threat actors with an easy way of spreading malware... potentially evading defenses due to its legitimate nature.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has highlighted a growing trend of threat actors abusing Microsoft's ClickOnce technology, a legitimate application deployment mechanism, to facilitate the distribution of malware. Published on June 18, 2026, this first part of a two-part series focuses on the technical underpinnings of ClickOnce application deployment, explaining how it enables developers to package, distribute, and update applications with minimal user interaction and without requiring administrative privileges. This inherent design, while beneficial for legitimate software distribution, makes ClickOnce an attractive channel for adversaries to deploy malicious applications. The abuse of this trusted, built-in Windows feature allows threat actors to bypass traditional security controls, enabling initial access and execution of malicious code on target systems by leveraging the legitimate nature of the technology, thus enhancing defense evasion capabilities.

## Attack Chain

This brief is part one of a series detailing the internal workings of ClickOnce technology. It focuses on the legitimate deployment process rather than a specific observed attack chain. The methods by which threat actors exploit these mechanisms for malicious purposes will be detailed in the subsequent part of this series.

## Impact

Should threat actors successfully weaponize ClickOnce applications, the impact could be substantial. The technology's design enables applications to be deployed and installed with "minimal user interaction" and "no elevated privileges required," meaning malicious payloads could be delivered stealthily and widely without raising immediate suspicion. This could lead to widespread malware infections, data exfiltration, establishment of persistence, and further compromise of victim networks, especially given the ease with which users might be tricked into executing what appears to be a legitimate application or update. The legitimate nature of ClickOnce also complicates detection, increasing the success rate of such attacks across various Windows environments.

## Recommendation

*   Educate users about the risks associated with downloading and executing applications from untrusted sources, even if they appear to use legitimate deployment mechanisms like ClickOnce.
*   Implement application whitelisting solutions to restrict the execution of unauthorized applications, including potentially malicious ClickOnce deployments.
*   Ensure endpoint detection and response (EDR) solutions are configured to monitor and alert on suspicious activity related to ClickOnce processes or the execution of applications signed by unknown publishers.
*   Regularly review and audit logs for application deployment events, paying close attention to sources and publishers of ClickOnce applications.
