---
title: Critical Remote Code Execution Vulnerabilities in Adobe Illustrator
slug: 2026-09-adobe-illustrator-vulnerabilities
description: Three vulnerabilities in Adobe Illustrator allow for remote code execution when a user opens a maliciously crafted file, potentially granting an attacker full control over the host system.
date: "2026-09-10T07:10:32Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - vulnerability
  - code-execution
  - adobe
  - graphical-editing
vendors:
  - Adobe
products:
  - Illustrator
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
    evidence: De kwetsbaarheden in Adobe Illustrator kunnen worden misbruikt door een aanvaller die een speciaal gemaakt bestand naar jou stuurt.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Wanneer je dit bestand opent in Adobe Illustrator, kan de aanvaller schadelijke programma's op je computer laten uitvoeren.
    confidence_band: high
references:
  - https://www.ncsc.nl/alerts/kwetsbaarheden-in-adobe-illustrator-met-risico-op-code-uitvoering-update-onmiddellijk
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Deploy latest Adobe security updates across all instances of Illustrator.
      owner: IT Operations
      due: 24h
      evidence: NCSC advises to install updates as soon as possible.
  hunt_leads:
    - lead: Search for suspicious child processes originating from Illustrator.exe or Illustrator process tree.
      technique_id: T1204.002
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attacker can run malicious programs on the computer.
  mitigation_plan:
    - priority: immediate
      action: Install latest security updates from Adobe.
      owner: IT Operations
      addresses: Adobe Illustrator vulnerabilities
      evidence: Adobe has released security updates that resolve these vulnerabilities.
---

On September 10, 2026, the NCSC-NL published an alert regarding three high-severity vulnerabilities found in Adobe Illustrator. These vulnerabilities, carrying CVSS scores between 7.8 and 8.6, enable an attacker to achieve arbitrary code execution on a target system. The primary vector for exploitation is the delivery of a specially crafted file to a victim. When the victim opens the malicious file within Adobe Illustrator, the application processes the malformed data in a way that triggers code execution under the context of the user running the application.

If successfully exploited, an attacker could gain complete control over the affected workstation. This includes the ability to view, modify, or delete files, as well as the capacity to install further malicious software, such as infostealers, backdoors, or ransomware. There is no evidence at this time of active, in-the-wild exploitation. Adobe has released security updates to patch these flaws, and immediate deployment is recommended to mitigate the risk of compromise.

## Impact

Successful exploitation allows an attacker to gain unauthorized access to the victim's machine. The impact includes full compromise of the user's data, potential exfiltration of sensitive information, and the persistence of further malware on the target system. These vulnerabilities pose a significant risk to organizations where users frequently handle external graphics files, as the attack requires minimal interaction beyond opening a file.

## Recommendation

* Immediately apply the security updates provided by Adobe for the affected Illustrator versions.
* Coordinate with internal IT departments to verify software versions and ensure patch deployment is completed across all endpoints.
* Monitor endpoint telemetry for unusual child processes spawned by Illustrator (e.g., cmd.exe, powershell.exe, wscript.exe) following the opening of document files.
