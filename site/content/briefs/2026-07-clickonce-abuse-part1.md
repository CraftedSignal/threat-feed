---
title: Threat Actors Abusing Microsoft ClickOnce Technology for Malware Distribution
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are leveraging Microsoft's legitimate ClickOnce technology, designed for simplified, low-privilege application installation and updates, to easily distribute and execute malware on Windows systems, bypassing traditional security controls and aiding in defense evasion.
date: "2026-07-04T07:40:18Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - deployment
  - microsoft
  - abuse
  - windows
  - malware
  - defense-evasion
vendors:
  - Microsoft
products:
  - ClickOnce technology
  - Microsoft Store
  - Windows Installer
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: 'Its scope is therefore twofold: It provides developers with a streamlined way to distribute applications across different environments, and it offers users a standardized mechanism to execute (and optionally install) software.'
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has highlighted a new abuse vector leveraging Microsoft's ClickOnce technology, a legitimate application deployment mechanism designed for simplified software distribution on Windows systems. While intended to facilitate user-friendly installation and updates without requiring administrative privileges, ClickOnce's "click-once" deployment model presents an attractive avenue for threat actors to spread malware. This initial part of a two-part series (published 2026-07-04) delves into the internal workings of ClickOnce, explaining how applications are published, deployed, and potentially installed by users with minimal interaction, often triggered directly from a web browser. The core concern for defenders is that this method could be exploited to bypass traditional security controls and facilitate defense evasion by masquerading malicious payloads within a trusted framework.

## Attack Chain

[Attack Chain omitted as the source describes the technology's inner workings and potential for abuse, not an observed, specific attack chain by threat actors. Part 2 of the series is expected to cover weaponization methods.]

## Impact

Successful exploitation of ClickOnce technology by threat actors would lead to the easy distribution and execution of malware on Windows endpoints. The core impact stems from ClickOnce's design to allow application deployment without elevated privileges and with minimal user interaction, meaning users could unknowingly install malicious software by simply clicking a link, bypassing common security prompts. This facilitates initial access, execution of arbitrary code, and persistence, allowing adversaries to establish footholds, exfiltrate data, or deploy ransomware without triggering traditional installation alerts or requiring UAC elevation. The technology's self-updating feature could also be leveraged to maintain persistence and deliver updated malicious payloads.

## Recommendation

*   Review and understand the legitimate use and deployment mechanisms of ClickOnce technology within your organization to identify potential anomalous activity.
*   Ensure robust endpoint detection and response (EDR) solutions are deployed and configured to monitor process creation, network connections, and file modifications on Windows systems, particularly those originating from web browsers and leading to application deployments.
*   Focus on logging application deployment activities, specifically process creation events that indicate ClickOnce application execution (e.g., processes launched by `dfsvc.exe` or `mscorsvw.exe` for .NET applications), to enable future detection of malicious ClickOnce payloads.
