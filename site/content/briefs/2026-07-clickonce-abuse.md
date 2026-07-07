---
title: New Abuse of ClickOnce Technology for Malware Distribution
slug: 2026-07-clickonce-abuse
description: Threat actors are abusing Microsoft's ClickOnce technology, a legitimate application deployment method, to spread malware. ClickOnce allows applications to be deployed, installed, and updated with minimal user interaction and without requiring administrative privileges, making it an attractive vector for adversaries to achieve initial access, execute malicious code, and potentially establish persistence on a system.
date: "2026-07-07T15:30:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - windows
  - application-deployment
  - malware-distribution
  - clickonce
vendors:
  - Microsoft
products:
  - ClickOnce technology
  - Visual Studio
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: ClickOnce's user-friendly deployment process is a double-edged sword — while it simplifies software deployment for legitimate developers, it also provides threat actors with an easy way of spreading malware.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Developers can share one of the ClickOnce deployment files, on which the user would only have to 'click once' to deploy the application.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Whether or not the application should be available offline, which determines if the application should only be executed, or also installed into the system
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: Signed Binary Proxy Execution
    evidence: No elevated privileges required to perform the deployment
    confidence_band: med
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has identified a new abuse vector leveraging Microsoft's ClickOnce technology for malware distribution. ClickOnce, designed to simplify application deployment by allowing users to install and update software with minimal interaction and without administrative privileges, has become an attractive mechanism for threat actors. This initial report, part one of a two-part series published on July 7, 2026, delves into the internal workings of ClickOnce, detailing how applications are packaged, distributed, and installed. The ease of deployment, a core feature for legitimate developers using tools like Visual Studio, inadvertently creates a low-friction pathway for adversaries to deliver malicious payloads, circumventing traditional security barriers. This research is noted as the first public documentation of ClickOnce internals in the context of threat abuse.

## Attack Chain

This brief describes the legitimate deployment process of ClickOnce applications, which attackers can abuse. Specific weaponization methods and attack chains are detailed in Part 2 of the series.

## Impact

The abuse of ClickOnce technology significantly lowers the barrier for entry for threat actors, enabling them to distribute malware more efficiently and potentially bypass security controls that rely on elevated privileges or traditional installation methods. If successfully exploited, this can lead to widespread initial access for various malicious payloads, including ransomware, information stealers, and backdoors, impacting a broad range of users across different sectors who might be tricked into executing seemingly legitimate applications. While specific victim counts or sectors are not detailed in this initial report, the inherent design of ClickOnce makes it a potent tool for mass malware deployment.

## Recommendation

This brief focuses on the technical underpinnings of ClickOnce abuse rather than providing specific detection artifacts in this first part of the research. Part 2 of this series is expected to offer detection strategies.
