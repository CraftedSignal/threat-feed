---
title: Threat Actors Abusing Microsoft's ClickOnce Technology for Malware Delivery
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are exploiting Microsoft's legitimate ClickOnce application deployment technology to spread malware, leveraging its ability to install applications with minimal user interaction and no administrative privileges, posing a significant risk for organizations.
date: "2026-07-07T15:56:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-delivery
  - user-execution
  - windows
  - endpoint
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
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application.'
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1072
    technique_name: Software Deployment Tools
    evidence: While it simplifies software deployment for legitimate developers, it also provides threat actors with an easy way of spreading malware.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

Threat actors are increasingly abusing Microsoft's ClickOnce technology, a legitimate software deployment mechanism, as an easy vector for malware delivery. ClickOnce simplifies application distribution by allowing users to run and install applications with a single click, often bypassing the need for administrative privileges. While designed for developer convenience, this user-friendly approach makes it attractive for attackers looking to spread malicious software. The abuse stems from ClickOnce's core functionality, which allows deployment files (`.application` manifests) to be hosted on arbitrary web servers and executed by users, potentially installing unwanted applications without robust security prompts if the publisher's signature is not properly verified. This enables widespread targeting and facilitates quick infiltration, making it a critical concern for defenders.

## Attack Chain

This brief, "Part 1," focuses on the inner workings of the ClickOnce technology and its potential for abuse rather than a specific attack chain. Therefore, a detailed step-by-step attack chain of malicious exploitation is not provided within this document. The subsequent "Part 2" is expected to detail specific weaponization methods.

## Impact

The successful abuse of ClickOnce technology for malware delivery can lead to various severe impacts, including initial system compromise, data exfiltration, ransomware deployment, or the establishment of persistent backdoors. While specific victim counts or targeted sectors are not detailed in this initial report, the broad applicability and ease of deployment offered by ClickOnce make it a potent tool for attackers targeting any Windows environment. If unmitigated, this vector could lead to widespread infections and significant financial and reputational damage for affected organizations, as it enables attackers to bypass traditional security controls that rely on elevated privileges or complex installation procedures.

## Recommendation

*   Implement robust endpoint monitoring for `dfsvc.exe` and `rundll32.exe` process creation and network connections, focusing on unusual parent-child relationships or suspicious command-line arguments, as these binaries are central to ClickOnce application deployment.
*   Configure network and endpoint security solutions to monitor and potentially block the download and execution of `.application` manifest files from untrusted or unverified sources.
*   Prioritize user education regarding the risks associated with executing ClickOnce applications, particularly those that do not display a verifiable publisher signature or originate from unexpected locations.
*   Review and enforce application whitelisting policies to restrict the execution of unauthorized ClickOnce applications.
