---
title: Threat Actors Abuse Microsoft ClickOnce for Initial Access and Persistence
slug: 2026-07-clickonce-abuse
description: Threat actors are abusing Microsoft ClickOnce to gain initial access, execute malware, and maintain persistence through deceptive deployment manifests, .appref-ms shortcuts, scheduled tasks, and the ClickOnce update path.
date: "2026-07-07T08:34:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - clickonce
  - windows
  - persistence
  - initial-access
  - defense-evasion
  - malware
vendors:
  - Microsoft
products:
  - ClickOnce
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Actors can deliver malicious ClickOnce deployment links or .application files through phishing pages and other social engineering paths.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: ClickOnce can execute after minimal user interaction and does not require local administrator privileges.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Attackers can place .appref-ms shortcuts in Startup locations to relaunch the ClickOnce application.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
    evidence: Attackers can create scheduled tasks that execute malicious .appref-ms files.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1218
    technique_name: System Binary Proxy Execution
    evidence: Payload activity can appear under legitimate Microsoft process trees such as dfsvc.exe and rundll32.exe.
    confidence_band: medium
updates:
  - at: "2026-06-20T15:38:30Z"
    level: L1
    summary: CrowdStrike Part 1 described ClickOnce deployment mechanics and abuse potential.
    sources:
      - crowdstrike
  - at: "2026-06-21T05:21:58Z"
    level: L2
    summary: CrowdStrike Part 2 added persistence, .appref-ms shortcut, scheduled task, and update-abuse details.
    sources:
      - crowdstrike
references:
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-one/
  - https://www.crowdstrike.com/en-us/blog/new-abuse-of-the-clickonce-technology-part-two/
rules:
  - title: Detect ClickOnce .appref-ms Persistence via Startup Folder
    description: Detects creation or modification of ClickOnce application reference files in a user's Startup folder.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
  - title: Detect ClickOnce .appref-ms Persistence via Scheduled Task Creation
    description: Detects scheduled task creation that executes a ClickOnce application reference file.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1053.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Threat actors are abusing Microsoft's ClickOnce deployment technology to run malware and maintain access on Windows systems. ClickOnce is attractive because it can be launched from a web link or `.application` file, needs only limited user interaction, and normally does not require local administrator privileges.

CrowdStrike's ClickOnce research was originally catalogued as multiple briefs. This page now tracks the ClickOnce activity as one brief and records the Part 1 and Part 2 coverage as updates rather than separate public entries.

## Attack Chain

1. An attacker prepares a malicious ClickOnce deployment and hosts the deployment manifest or associated application files.
2. The attacker delivers the deployment path through phishing, a deceptive web page, a compromised site, or another social engineering channel.
3. The victim launches the ClickOnce flow by clicking a link or opening a `.application` file.
4. Windows invokes ClickOnce components such as `dfsvc.exe` to retrieve and execute the application.
5. The malicious payload runs under a legitimate-looking Microsoft process chain, reducing the visibility of the initial execution path.
6. The attacker establishes persistence by placing an `.appref-ms` shortcut in a Startup location or by creating a scheduled task that launches the shortcut.
7. The attacker can use the ClickOnce update mechanism to refresh payloads or infrastructure when the application is launched again.

## Impact

Successful abuse gives an attacker a low-friction execution and persistence path on Windows endpoints. The technique can bypass controls focused on traditional executable delivery, hide activity behind trusted process names, and keep a foothold alive through ClickOnce updates.

## Recommendation

* Monitor execution of ClickOnce deployment files and unexpected child processes from `dfsvc.exe`, `rundll32.exe`, and related Microsoft deployment components.
* Alert on `.appref-ms` files written to user Startup folders and scheduled tasks that launch `.appref-ms` targets.
* Restrict ClickOnce execution from untrusted locations where possible through application control or software restriction policy.
* Review outbound connections from ClickOnce-related process trees to unknown or newly observed infrastructure.
