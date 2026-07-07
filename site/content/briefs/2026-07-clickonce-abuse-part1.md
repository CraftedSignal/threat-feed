---
title: 'New Abuse of ClickOnce Technology: Inner Workings for Malware Distribution'
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are actively leveraging Microsoft's ClickOnce deployment technology, a mechanism designed for user-friendly application distribution without administrative privileges, to spread malware by packaging malicious software for simplified execution and installation on victim systems.
date: "2026-07-07T11:45:49Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - clickonce
  - malware
  - windows
  - microsoft
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
    evidence: ClickOnce's user-friendly deployment process is a double-edged sword — while it simplifies software deployment for legitimate developers, it also provides threat actors with an easy way of spreading malware.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: The 'deployment' refers to the execution of a ClickOnce application and its potential installation onto the system afterward.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has identified a new abuse vector involving Microsoft's ClickOnce technology, a deployment mechanism intended to simplify application distribution and updates for developers. This technology allows applications to be published and installed with minimal user interaction and often without requiring administrative privileges, making it a "double-edged sword" for security. While Part 1 of this series, published on June 18, 2026, focuses on explaining the internal mechanics of ClickOnce application deployment, it highlights how its core features—such as simplified installation and automatic updates—make it an attractive target for threat actors looking to bypass traditional security controls and spread malicious software. Defenders need to understand these inner workings to anticipate and detect the malicious deployment of ClickOnce applications.

## Impact

The abuse of ClickOnce technology facilitates the easy distribution and execution of malware, bypassing typical installation hurdles that require elevated privileges. If exploited, it enables threat actors to install persistent malicious applications on user endpoints with a single click, leading to potential data theft, system compromise, or further network infiltration. The user-friendly nature of ClickOnce deployment means that victims may inadvertently install malware simply by interacting with what appears to be a legitimate application installation prompt, leading to widespread compromise across targeted organizations.

## Recommendation

*   Understand the fundamental deployment process of ClickOnce applications as detailed in this brief to anticipate potential attack vectors.
*   Prepare for future recommendations by ensuring endpoint logging (e.g., process creation, network connections) is enabled and comprehensive on Windows systems.
*   Familiarize security teams with the indicators of ClickOnce application installations, such as specific file types (`.application`, `.manifest`), to aid in future detection efforts.
