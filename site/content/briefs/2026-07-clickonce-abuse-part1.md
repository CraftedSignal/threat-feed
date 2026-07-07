---
title: 'New Abuse of ClickOnce Technology, Part 1: Inner Workings Detailed'
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are leveraging Microsoft's ClickOnce technology, designed for simplified application deployment, as a mechanism to distribute malware and bypass administrative privilege requirements, posing a significant risk to endpoint security.
date: "2026-07-07T04:57:22Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - microsoft
  - deployment
  - malware
  - endpoint
  - windows
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
    evidence: Developers can share one of the ClickOnce deployment files, on which the user would only have to “click once” to deploy the application.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has identified a new abuse vector leveraging Microsoft's ClickOnce technology, a deployment mechanism designed to simplify application distribution and updates without requiring administrative privileges. This first part of a two-series brief details the fundamental workings of ClickOnce, explaining how applications are published and deployed on user endpoints. The inherent features of ClickOnce, such as minimal user interaction and no elevated privileges for installation, make it an attractive target for threat actors seeking to distribute malware effectively. Understanding these internal mechanisms, including the role of deployment manifests (.application files), is crucial for defenders to anticipate and detect malicious use cases that will be elaborated in subsequent research.

## Impact

The primary impact of ClickOnce abuse stems from its ability to facilitate easy malware distribution and installation. Because ClickOnce applications require minimal user interaction and no administrative privileges, attackers can bypass common security hurdles, leading to rapid compromise of user endpoints. Successful exploitation could result in various forms of compromise, including data exfiltration, system control, or deployment of ransomware, affecting any organization where Windows endpoints are used.

## Recommendation

* Review the ClickOnce deployment process, including `.application` manifest files and related components, as detailed in this brief, to establish a baseline understanding of legitimate activity.
* Prepare to implement detection strategies for malicious ClickOnce application deployments as further research (e.g., Part 2 of this series) becomes available.
