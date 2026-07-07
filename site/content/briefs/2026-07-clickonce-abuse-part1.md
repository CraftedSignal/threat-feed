---
title: 'New Abuse of the ClickOnce Technology, Part 1: The Inner Workings of ClickOnce Application Deployment'
slug: 2026-07-clickonce-abuse-part1
description: Threat actors are actively abusing Microsoft's user-friendly ClickOnce technology to distribute malware, simplifying the infection process for malicious applications onto user endpoints through methods like clicking a web-based 'Install' button, which allows for easy execution of malicious files and bypassing of administrative privileges, as detailed by CrowdStrike.
date: "2026-07-06T08:33:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - malware-distribution
  - microsoft
  - windows
  - initial-access
  - execution
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
    evidence: Threat actors are abusing this user-friendly mechanism to distribute malware, simplifying the infection process for malicious applications onto user endpoints through methods like clicking a web-based 'Install' button, allowing for easy execution of malicious files.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Threat actors are abusing this user-friendly mechanism to distribute malware, simplifying the infection process for malicious applications onto user endpoints through methods like clicking a web-based 'Install' button, allowing for easy execution of malicious files.
    confidence_band: high
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
---

CrowdStrike has observed new abuse of Microsoft's ClickOnce technology by threat actors, leveraging its design for simplified application deployment to distribute malware. ClickOnce, originally designed to enable developers to package and distribute applications that users can run, install, and automatically update with minimal interaction and without requiring administrative privileges, presents a double-edged sword. While it streamlines software distribution for legitimate purposes, its user-friendly nature makes it an attractive vector for malicious activity. This first part of a two-part series details the internal mechanisms of ClickOnce application deployment, from publication to installation on the user's endpoint, laying the groundwork for understanding its security implications. Part 2 is expected to cover specific weaponization methods, previously unknown abuse techniques, and detection strategies against these attacks.

## Impact

The abuse of ClickOnce technology significantly lowers the barrier for entry for threat actors to infect user endpoints with malware. By packaging malicious applications as ClickOnce deployments, attackers can trick users into installing and executing software with minimal interaction and without needing administrative privileges, bypassing traditional security controls and user-access policies. If successful, this can lead to widespread distribution of various malware types, including stealers, ransomware, or backdoors, resulting in data exfiltration, system compromise, or financial losses across targeted organizations and individuals.

## Recommendation

*   Familiarize security teams and detection engineers with the internal workings of the ClickOnce technology, as detailed in this brief, to better understand potential attack vectors.
*   Prepare for specific detection strategies against malicious ClickOnce applications expected to be detailed in Part 2 of this series.
*   Review the described mechanics of ClickOnce application deployment to understand potential vectors for user execution (T1204.002).
