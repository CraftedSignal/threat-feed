---
title: Threat Actors Leveraging ClickOnce for Malware Deployment
slug: 2026-07-clickonce-abuse-part-1
description: Threat actors are exploiting Microsoft's ClickOnce technology, a legitimate application deployment mechanism, to distribute malware by leveraging its user-friendly installation process, potentially bypassing security controls and establishing persistence.
date: "2026-07-06T08:13:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - technology-abuse
  - windows
  - clickonce
  - malware-delivery
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
    technique_name: Drive-by Compromise
    evidence: When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204.001
    technique_name: 'Drive-by Compromise: Malicious Link'
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to ''click once'' to deploy the application.'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Whether or not the application should be available offline, which determines if the application should only be executed, or also installed into the system
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Self-updating functionality allowing applications to automatically fetch and install updates from the deployment server
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has highlighted the increasing abuse of Microsoft's ClickOnce technology by threat actors to facilitate malware distribution. ClickOnce is a deployment solution designed to simplify the installation and updating of Windows applications, enabling users to run and install software with minimal interaction and often without requiring administrative privileges. While beneficial for legitimate developers, these features make ClickOnce an attractive vector for adversaries seeking to bypass traditional security controls and deploy malicious applications. This analysis (Part 1 of a two-part series) delves into the internal workings of ClickOnce, explaining its publication and deployment journey, setting the stage for understanding how its mechanics can be weaponized for initial access, execution, and persistence. The report does not detail specific campaigns or threat actors but focuses on the technology itself as a potential threat vector.

## Attack Chain

1.  **Initial Access via Malicious Hosting**: A threat actor hosts a malicious ClickOnce deployment file (an `.application` manifest) on a compromised or purpose-built website.
2.  **User Lure and Click**: The attacker social engineers a victim, often through phishing, to visit the malicious website and click an "Install" button or similar call to action.
3.  **Deployment File Download**: Upon clicking, the victim's browser downloads the `.application` ClickOnce deployment manifest, which acts as a descriptor for the malicious application.
4.  **Execution Request and User Prompt**: The operating system or .NET runtime processes the downloaded `.application` file, initiating the deployment and presenting the user with a prompt for confirmation. If the publisher's signature cannot be verified, the OS will alert the user.
5.  **User Confirmation**: The victim, either tricked or accustomed to similar prompts, confirms the deployment, allowing the ClickOnce application to proceed with its installation process.
6.  **Malicious Application Deployment**: The malicious ClickOnce application is deployed to the user's system. Depending on the configuration, it can be executed immediately or installed for offline availability, establishing a foothold.
7.  **Persistence and Payload Delivery**: The installed malicious ClickOnce application leverages its self-updating functionality to automatically fetch additional malicious payloads, maintain persistence, or communicate with an attacker-controlled deployment server.

## Impact

The abuse of ClickOnce technology allows threat actors to deliver malware to victim systems, potentially bypassing security mechanisms that might flag traditional executable downloads. If successful, this can lead to system compromise, data exfiltration, or the deployment of further malicious stages like ransomware. The ease of deployment, minimal user interaction, and lack of administrative privilege requirements mean that a wide range of users across various sectors could be susceptible. The report does not specify observed victim numbers or targeted sectors but emphasizes the potential for widespread abuse due to the technology's widespread availability and simplified deployment model.

## Recommendation

*   Educate users on the risks associated with downloading and installing applications from untrusted sources, even if they appear to use legitimate deployment technologies like ClickOnce.
*   Implement strong application whitelisting policies to prevent the execution of unauthorized ClickOnce applications, specifically monitoring for `*.application` file executions not from trusted sources.
*   Monitor for process creation events where `dfsvc.exe` (the ClickOnce Deployment Support Service) initiates unusual child processes or network connections, as this service is key to ClickOnce deployments.
*   Enable comprehensive logging for web activity (category: webserver, product: any) to detect downloads of `.application` files from suspicious or untrusted domains.
