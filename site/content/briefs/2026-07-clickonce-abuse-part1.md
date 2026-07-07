---
title: Threat Actors Abuse Microsoft ClickOnce for Malware Distribution
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are exploiting Microsoft's ClickOnce technology, a legitimate application deployment feature, to distribute malware by packaging malicious applications that users can install without administrative privileges, posing a significant risk for initial access and execution on Windows endpoints.
date: "2026-07-04T11:00:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - windows
  - malware-distribution
  - deployment-abuse
vendors:
  - Microsoft
products:
  - ClickOnce
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application. These deployment files can be hosted on the vendor''s website, where they introduce their app alongside an “Install” button. When clicked, the button triggers the download of the ClickOnce deployment file...'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application. These deployment files can be hosted on the vendor''s website, where they introduce their app alongside an “Install” button. When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.'
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

This brief details how threat actors can abuse Microsoft's ClickOnce technology, a legitimate deployment mechanism for Windows applications. ClickOnce is designed to simplify application distribution and updates, allowing users to install software with minimal interaction and typically without requiring administrative privileges. While beneficial for developers, this ease of deployment creates a potent vector for attackers to spread malware. Part 1 of this CrowdStrike analysis focuses on the underlying technical mechanisms of ClickOnce deployment, explaining how applications are published, hosted, and installed on user endpoints. This foundational understanding is crucial for defenders to anticipate and detect malicious use of this technology, which can facilitate initial access and execution of attacker-controlled code.

## Attack Chain

1.  **Develop Malicious Application**: An attacker develops or procures a malicious application (e.g., a dropper, stealer, or remote access Trojan) intended for distribution.
2.  **Publish via ClickOnce**: The attacker uses a tool like Visual Studio's ClickOnce publishing wizard to package the malicious application, configuring deployment parameters such as hosting location and update settings. This process generates the necessary ClickOnce deployment files, including the `.application` manifest.
3.  **Host Deployment Files**: The generated ClickOnce deployment files, particularly the `.application` manifest, are hosted on an attacker-controlled web server or network share.
4.  **Initial Access via Lure**: The attacker employs social engineering tactics (e.g., phishing emails, malicious advertisements, compromised websites) to entice a target user to click a link that points to the hosted `.application` file or a webpage containing an "Install" button for it.
5.  **User Confirmation**: Upon clicking the link, the Windows operating system initiates the ClickOnce deployment process. If the application's publisher cannot be verified (a common scenario for malicious apps), the OS prompts the user for confirmation to proceed with the installation.
6.  **Application Deployment and Execution**: If the user confirms, the ClickOnce runtime (often leveraging the `dfsvc.exe` service) deploys the application locally, installs it (if configured for offline use), and then executes the application. This deployment typically bypasses the need for elevated administrative privileges.
7.  **Malicious Payload Execution**: The executed malicious ClickOnce application proceeds to perform its intended actions, such as establishing persistence, downloading secondary malware, exfiltrating sensitive data, or joining a botnet.

## Impact

The abuse of ClickOnce technology allows threat actors to bypass traditional software installation hurdles, enabling the widespread distribution of malware with minimal user friction and without requiring administrative privileges. If successful, organizations face immediate risks of system compromise, data exfiltration, ransomware infection, or further network penetration. The legitimate nature of ClickOnce can make detection challenging, increasing the likelihood of successful breaches and compromising the integrity and confidentiality of targeted systems and data.

## Recommendation

*   Enable comprehensive logging for `process_creation` events, specifically monitoring for instances of `dfsvc.exe` executing untrusted or unsigned applications.
*   Implement application whitelisting policies that restrict the execution of ClickOnce applications from untrusted sources or those lacking valid digital signatures.
*   Educate users on the risks associated with installing applications from unverified publishers, particularly when prompted by the operating system during a ClickOnce deployment.
*   Monitor network traffic for connections initiated by ClickOnce applications to suspicious or unknown domains that could indicate command and control activity.
