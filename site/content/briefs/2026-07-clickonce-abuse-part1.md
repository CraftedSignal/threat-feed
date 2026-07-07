---
title: Understanding ClickOnce Technology Abuse - Part 1
slug: 2026-07-clickonce-abuse-part1
description: CrowdStrike researchers detail the internal workings of Microsoft's ClickOnce technology, highlighting its design for simplified application deployment and updates without administrative privileges, which threat actors can abuse for easy malware distribution by leveraging legitimate application manifest and deployment processes.
date: "2026-07-07T07:05:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - microsoft
  - windows
  - deployment
  - software-supply-chain
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
    evidence: developers can share one of the ClickOnce deployment files, on which the user would only have to 'click once' to deploy the application.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: developers can share one of the ClickOnce deployment files, on which the user would only have to 'click once' to deploy the application.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: When clicked, the button triggers the download of the ClickOnce deployment file, and after some prerequisites are met, directly initiates the deployment.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has identified a potential new avenue for abuse involving Microsoft's ClickOnce technology, a deployment mechanism designed to simplify application distribution and updates without requiring administrative privileges. This first part of their research details the inner workings of ClickOnce, explaining how developers package and export software into ClickOnce-compatible resources, and how these applications are deployed on user endpoints. While intended for legitimate software, ClickOnce's 'minimal user interaction' and 'no elevated privileges' features present an attractive method for threat actors to distribute malware. The technology, which involves `.application` manifest files and the `dfsvc.exe` process, streamlines software delivery, inadvertently creating an easy vector for threat actors to spread malicious applications. Defenders need to understand these underlying mechanics to anticipate and detect future weaponization of this technology, which will be further elaborated in Part 2 of this series.

## Attack Chain

1.  Attacker develops a malicious application (e.g., an information stealer, backdoor, or ransomware dropper).
2.  The malicious application is compiled and published using Microsoft's ClickOnce technology, generating a `.application` deployment manifest and associated files.
3.  These ClickOnce deployment files are hosted on attacker-controlled infrastructure, such as a malicious website or network file share.
4.  The attacker initiates a social engineering campaign (e.g., phishing email, malicious advertisement, or watering hole attack) to lure victims into interacting with the hosted ClickOnce application.
5.  Upon user interaction (e.g., clicking an "Install" button on a webpage or directly accessing the `.application` file), the system’s .NET Framework initiates `dfsvc.exe` to process the `.application` deployment manifest.
6.  `dfsvc.exe` downloads the necessary application files to the client system and, potentially after a user confirmation if the publisher is unsigned, proceeds with the installation and execution.
7.  The malicious ClickOnce application is deployed and run on the victim's system, leveraging the legitimate ClickOnce execution environment, often without requiring administrative privileges for the deployment itself.
8.  The malicious application executes its payload, leading to initial access, establishing persistence, or achieving objectives like data exfiltration or system compromise.

## Impact

The successful abuse of ClickOnce technology could lead to widespread malware distribution, as it bypasses traditional installation hurdles by requiring minimal user interaction and no administrative privileges. This significantly lowers the barrier for entry for threat actors, enabling them to deploy various types of malicious payloads, including ransomware, information stealers, and backdoors, across a broad victim base. The self-updating functionality inherent in ClickOnce applications further allows for continuous malware evolution and persistence for deployed threats. While Part 1 focuses on the technical mechanisms, the potential impact highlights an increased risk of initial access and execution for organizations where ClickOnce applications are permitted or commonly used.

## Recommendation

*   Monitor process creation events for `dfsvc.exe` (part of the .NET Framework), specifically noting unusual parent processes, command-line parameters, or execution from non-standard user profiles, as `dfsvc.exe` initiates ClickOnce application deployments.
*   Implement file event logging to detect the creation or modification of `.application` and other ClickOnce-related manifest files in suspicious locations, such as temporary internet files or user download directories, outside of expected legitimate application deployment paths.
