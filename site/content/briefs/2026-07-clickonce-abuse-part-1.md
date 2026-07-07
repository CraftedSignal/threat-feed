---
title: 'New Abuse of ClickOnce Technology: Part 1 - Inner Workings and Security Implications'
slug: 2026-07-clickonce-abuse-part-1
description: Threat actors are exploiting Microsoft's ClickOnce technology to deploy malware, leveraging its user-friendly, minimal-interaction application distribution model for initial access and execution of malicious code without requiring administrative privileges.
date: "2026-07-07T12:51:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - microsoft
  - clickonce
  - initial-access
  - execution
  - persistence
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
    evidence: ClickOnce's user-friendly deployment process is a double-edged sword — while it simplifies software deployment for legitimate developers, it also provides threat actors with an easy way of spreading malware.
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

CrowdStrike has observed a new abuse of Microsoft's ClickOnce technology, a deployment framework designed to simplify the distribution and installation of .NET applications. While intended for legitimate software distribution, ClickOnce's features — such as minimal user interaction, no administrative privileges requirement, and self-updating capabilities — make it an attractive vector for threat actors. This Part 1 brief details the internal mechanisms of ClickOnce, from application publishing to endpoint installation, laying the groundwork for understanding its security implications. Attackers can leverage these inherent design choices to spread malware, gain initial access, execute malicious payloads, and potentially maintain persistence on compromised Windows systems. This research serves as a foundational analysis before diving into specific weaponization methods in a subsequent Part 2.

## Attack Chain

This brief (Part 1) focuses on the internal workings of the ClickOnce technology and its legitimate deployment journey rather than a specific observed attack chain. It describes the technical foundation that threat actors could exploit, with specific abuse scenarios and weaponization methods expected to be detailed in a subsequent publication (Part 2). Therefore, a concrete step-by-step attack chain of observed malicious activity is not provided in this document.

## Impact

The abuse of ClickOnce technology facilitates the straightforward deployment of malicious applications, enabling threat actors to gain initial access and execute arbitrary code on target systems. Should an attack succeed, victims face potential data exfiltration, system compromise, and the installation of additional malware such as ransomware or espionage tools. The ability to install applications with minimal user interaction and without elevated privileges lowers the barrier for attackers, making a wider range of users vulnerable. While no specific victim counts or sectors are detailed in this part of the analysis, the widespread nature of Windows systems makes this a broad potential threat.

## Recommendation

*   Enable comprehensive endpoint logging, specifically for process creation events related to ClickOnce deployment, to detect unusual activity.
*   Monitor for the creation or execution of `.application` files (ClickOnce deployment manifests) in unexpected user directories or network shares, as described in the brief.
*   Implement application whitelisting policies to restrict the execution of unsigned or untrusted ClickOnce applications.
*   Educate users on the risks associated with executing applications from untrusted sources, even those presented through a seemingly legitimate "one-click" installation process that leverages the ClickOnce technology.
