---
title: 'New Abuse of ClickOnce Technology: Understanding Deployment Mechanisms'
slug: 2026-07-clickonce-abuse-part1
description: CrowdStrike details how Microsoft's ClickOnce application deployment technology, designed for simplified software distribution without administrative privileges, can be abused by threat actors to easily spread and install malware on user endpoints by tricking users into initiating the deployment.
date: "2026-07-05T06:38:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - windows
  - microsoft
  - application-deployment
  - malware-distribution
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
    evidence: The deployment can be as simple as clicking a webpage 'Install' button, and developers can share one of the ClickOnce deployment files, on which the user would only have to 'click once' to deploy the application.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: developers can share one of the ClickOnce deployment files, on which the user would only have to 'click once' to deploy the application.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1072
    technique_name: Software Deployment Tools
    evidence: ClickOnce is a deployment technology that enables developers to package and distribute applications... it also provides threat actors with an easy way of spreading malware.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

ClickOnce is a Microsoft application deployment technology designed to simplify software distribution and updates. It allows developers to package and distribute applications that users can install and run with minimal interaction and without requiring administrative privileges. While intended for legitimate software, its user-friendly deployment model, often initiated by a single click on a webpage "Install" button, makes it highly attractive to threat actors for spreading malware. This first part of a two-part series from CrowdStrike, published on July 5, 2026, details the fundamental internal workings of ClickOnce, from application publishing to its installation on user endpoints. It explains the core mechanisms that enable this technology, setting the stage for understanding how malicious actors can weaponize it, a topic to be covered in Part 2. Defenders should understand this foundational mechanism to anticipate and detect future ClickOnce-based threats.

## Attack Chain

1.  A developer (or threat actor) packages an application using Microsoft ClickOnce technology, typically through Visual Studio, generating core deployment files such as the `.application` manifest and associated application files.
2.  These ClickOnce deployment files are then hosted on a server, which can be a legitimate website or a malicious one masquerading as a trusted source.
3.  A user is directed to the hosting location (e.g., via a malicious link or social engineering) and initiates the deployment by clicking a designated "Install" button or directly accessing the `.application` file.
4.  The Windows operating system reviews the application's publisher information and may prompt the user for confirmation, particularly if the publisher's signature cannot be verified.
5.  Upon user confirmation, the ClickOnce deployment wizard proceeds to download and prepare the application for execution, appearing as a standard software installation process.
6.  The application is executed directly and can optionally be installed onto the user's system, facilitating malware execution and persistence without requiring elevated administrative privileges.

## Impact

The primary impact of ClickOnce abuse is the simplified and stealthy distribution and execution of malware on target systems. By leveraging ClickOnce’s design, threat actors can bypass traditional administrative privilege requirements for application installation, making it easier to compromise endpoints. This method allows for swift initial access and execution, potentially leading to data exfiltration, further system compromise, or ransomware deployment if the delivered malware has such capabilities. The ease of deployment also increases the success rate of social engineering campaigns, as users are accustomed to simplified installation prompts for legitimate software.

## Recommendation

*   Monitor process creation logs for the execution of `.application` files, especially when initiated from web browsers or untrusted network locations, to detect potential ClickOnce abuse.
*   Educate users about the risks associated with installing software from unverified sources, emphasizing caution when prompted for confirmation by application installers or web browsers.
