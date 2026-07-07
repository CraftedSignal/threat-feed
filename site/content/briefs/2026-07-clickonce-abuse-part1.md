---
title: 'New Abuse of the ClickOnce Technology, Part 1: The Inner Workings'
slug: 2026-07-clickonce-abuse-part1
description: CrowdStrike research details how Microsoft's ClickOnce deployment technology, designed for minimal user interaction, can be abused by threat actors to distribute malicious applications without requiring administrative privileges, enabling easy malware spread.
date: "2026-07-07T12:57:48Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - endpoint-security
  - windows
  - microsoft
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
    technique_id: T1204
    technique_name: User Execution
    evidence: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application.
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

CrowdStrike has published research detailing how Microsoft's ClickOnce technology, an application deployment mechanism, presents a significant vector for malware distribution by threat actors. ClickOnce is designed to simplify software deployment and updates, allowing users to install and run applications with minimal interaction, often by a single click from a web page, and crucially, without requiring administrative privileges. This user-friendly approach, while beneficial for legitimate developers, provides an attractive pathway for malicious actors to spread their payloads. This first part of CrowdStrike's series, published on June 18, 2026, focuses on the internal workings of ClickOnce, laying the groundwork for understanding how its features, such as self-contained packaging and automatic updates, can be weaponized. The implications for defenders are substantial, as the ease of deployment bypasses traditional security friction points, making it critical to understand the underlying mechanics to effectively detect and mitigate abuse.

## Attack Chain

1.  An attacker publishes a malicious application using ClickOnce technology, generating the necessary `.application` manifest and `.deploy` files.
2.  The attacker hosts these ClickOnce deployment files on an attacker-controlled website, often designed to mimic legitimate software distribution sites or brand pages.
3.  A victim is typically socially engineered (e.g., via phishing emails, malvertising, or compromised websites) to visit the attacker's malicious landing page.
4.  The victim clicks an "Install" or "Download" button on the webpage, triggering the download of the `.application` deployment manifest file.
5.  Windows initiates the ClickOnce deployment process, prompting the user for confirmation, which may include warnings about an unsigned or untrusted publisher.
6.  The victim proceeds by accepting or bypassing the security prompts, allowing the malicious ClickOnce application to execute and install itself on the system without requiring elevated administrative privileges.
7.  The malicious ClickOnce application executes its payload, establishing an initial foothold, downloading additional malware, or performing other harmful actions.
8.  The deployed malicious application can leverage ClickOnce's self-updating functionality to fetch new components or maintain persistence from attacker-controlled update servers.

## Impact

The primary impact of ClickOnce abuse is the simplified and stealthy distribution of malware to end-users. Because ClickOnce deployments require minimal user interaction and often bypass the need for administrative privileges, it significantly lowers the barrier for attackers to establish a foothold. If successful, victims could face data exfiltration, system compromise, ransomware deployment, or other malicious activities, all initiated by a seemingly innocuous "click once." While this brief doesn't detail specific campaigns or victim counts, the inherent design of ClickOnce makes it a highly scalable method for widespread compromise across various sectors.

## Recommendation

*   Enable Sysmon process-creation and network-connection logging to capture events related to ClickOnce application deployment and execution for potential future Sigma rules.
*   Implement Endpoint Detection and Response (EDR) solutions capable of monitoring `dfsvc.exe` and `rundll32.exe` activities, which are involved in ClickOnce processing.
*   Educate users about the risks of downloading and executing applications from untrusted sources, particularly when prompted by ambiguous publisher warnings during installation processes, as described in the "Attack Chain."
*   Ensure strong application whitelisting policies are in place to prevent the execution of unauthorized or unsigned ClickOnce applications on endpoints.
