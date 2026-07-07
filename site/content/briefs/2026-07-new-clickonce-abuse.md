---
title: New Abuse of ClickOnce Technology by Threat Actors
slug: 2026-07-new-clickonce-abuse
description: Threat actors are increasingly abusing Microsoft's ClickOnce technology to distribute malware, leveraging its streamlined application deployment capabilities to execute malicious software on user endpoints with minimal interaction and without requiring administrative privileges.
date: "2026-07-04T12:27:16Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware
  - windows
  - deployment
  - microsoft
vendors:
  - Microsoft
products:
  - ClickOnce technology
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'The concept is pretty straightforward: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application.'
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

Microsoft's ClickOnce is a deployment technology designed to simplify application distribution and updates, allowing users to install and run software with minimal interaction and without requiring administrative privileges. While intended for legitimate developers to easily share applications, its user-friendly deployment process presents a significant risk for abuse by threat actors. This initial brief, Part 1 of a series by CrowdStrike, delves into the underlying mechanisms of ClickOnce, detailing how applications are published and deployed. It highlights that the very features that make ClickOnce convenient – such as low-privilege execution and self-contained packaging – can be leveraged by attackers to efficiently spread and execute malicious software on user endpoints, sidestepping traditional installation hurdles.

## Impact

The abuse of ClickOnce technology significantly lowers the bar for threat actors to achieve initial access and execution on victim systems. By leveraging ClickOnce's design, attackers can distribute malware that users install by merely 'clicking once,' often bypassing the need for administrative privileges and potentially User Account Control (UAC) prompts. This enables widespread compromise, as malicious applications can appear legitimate and update automatically, facilitating persistence or the delivery of subsequent stage payloads. The self-contained packaging also means fewer dependencies, simplifying the attacker's deployment strategy and increasing the success rate of malware delivery across various Windows environments.

## Recommendation

Prioritized, concrete actions for detection engineering teams.
*   Familiarize yourselves with the legitimate functionality of ClickOnce deployment files (`.application` files) to understand potential baselines for abuse.
*   Monitor endpoint telemetry for suspicious executions originating from user-downloaded `.application` files, as these are the entry point for ClickOnce deployments.
*   Anticipate advanced detection strategies for ClickOnce abuse in Part 2 of this series from CrowdStrike, which will detail weaponization methods and detection techniques.
