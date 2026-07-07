---
title: 'New Abuse of the ClickOnce Technology, Part 1: The Inner Workings of ClickOnce Application Deployment'
slug: 2026-07-clickonce-abuse-part1
description: CrowdStrike details how Microsoft's ClickOnce technology, designed for simplified application deployment, presents an easy channel for threat actors to distribute malware by leveraging its user-friendly installation process that often requires minimal user interaction and no administrative privileges.
date: "2026-07-04T07:05:54Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - malware-distribution
  - windows
  - endpoint-security
  - threat-research
vendors:
  - Microsoft
products:
  - ClickOnce
  - Visual Studio
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: deployment files can be hosted on the vendor's website, where they introduce their app alongside an 'Install' button. When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: ClickOnce is a deployment technology that enables developers to package and distribute applications... provides threat actors with an easy way of spreading malware.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has published the first part of a series detailing the internals and potential abuse of Microsoft's ClickOnce technology. While ClickOnce is designed to simplify application deployment and updates for legitimate developers by offering minimal user interaction and no administrative privilege requirements, it concurrently provides an accessible vector for threat actors to spread malware. This analysis, published on June 18, 2026, focuses on the technology's core mechanics, including how applications are published and deployed. The inherent ease of deployment, often requiring just 'one click' from a user on a web page, makes it an attractive channel for adversaries seeking initial access and execution on target systems, paving the way for malicious software distribution.

## Attack Chain

1. **Preparation of Malicious Application:** A threat actor publishes a malicious application using ClickOnce technology, configuring deployment parameters like update locations and offline availability via tools like Visual Studio.
2. **Hosting of Deployment Files:** The attacker hosts the generated ClickOnce deployment files (e.g., the `.application` manifest file) on a malicious website or network share.
3. **User Lure/Initial Access:** The attacker entices a user to visit the malicious website and click an "Install" button or open the deployment file, initiating the deployment process.
4. **Security Prompt Bypass/Confirmation:** The operating system prompts the user for confirmation, especially if the publisher's signature cannot be verified; the user is social-engineered into confirming the deployment.
5. **Application Download & Execution:** The ClickOnce deployment mechanism downloads the application files and executes the malicious software on the user's endpoint.
6. **Installation (Optional but common):** Depending on the configuration, the malicious application can also install itself onto the system, establishing persistence.
7. **Malware Payload Delivery/Execution:** The executed malicious ClickOnce application performs its intended function, such as malware installation, data exfiltration, or further system compromise.

## Impact

While 'Part 1' of the CrowdStrike series does not detail specific victim counts or targeted sectors, it highlights that ClickOnce technology provides an "easy way of spreading malware" due to its streamlined and low-privilege deployment model. The primary impact stems from the potential for widespread malware distribution, enabling adversaries to gain initial access, execute malicious code, and potentially establish persistence on user endpoints with minimal user interaction, leading to various forms of compromise such as data theft, ransomware infection, or further network infiltration.

## Recommendation

*   Ensure comprehensive `process_creation` logging is enabled on Windows endpoints to capture the execution of ClickOnce applications and their child processes.
*   Implement file system monitoring for the creation of new `.application` and `.manifest` files in unusual user directories, which may indicate rogue ClickOnce deployments.
