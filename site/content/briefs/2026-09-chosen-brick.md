---
title: Iranian State Cyber Activity Targeting Dissidents via CHOSEN BRICK Malware
slug: 2026-09-chosen-brick
description: Iranian state-sponsored actors are using the modular CHOSEN BRICK malware to target dissidents, journalists, and activists globally, employing social engineering and legitimate cloud services for exfiltration.
date: "2026-09-15T19:04:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - surveillance
  - espionage
  - malware
  - social-engineering
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The actor often purports to be an individual previously known to the target or technical support from the social messaging platform.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: CHOSEN BRICK is persistent and will survive a reboot of the target device. To do this it uses registry keys, most often the Run key.
    confidence_band: high
references:
  - https://www.ncsc.gov.uk/news/iranian-cyber-targeting-of-dissidents-activists-and-journalists
iocs:
  - type: domain
    value: api.telegram.org
  - type: domain
    value: backblazeb2.com
  - type: domain
    value: vultrobjects.com
  - type: domain
    value: storjshare.io
  - type: domain
    value: iproyal.com
  - type: domain
    value: lightningproxies.net
ioc_counts:
  domain: 6
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy hunting queries for registry modifications to HKCU Run keys and unusual Microsoft Defender exclusions.
      owner: Detection Engineering
      due: 24h
      evidence: Source provides specific registry paths and evasion tactics.
  hunt_leads:
    - lead: Search for processes executing from non-standard locations like C:\Windows\SysWOW64 (note the space character).
      technique_id: T1204
      data_needed:
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The most common observed is C:\Windows \SysWOW64; note there is a space after Windows.
---

Since at least 2025, Iranian state-linked cyber actors have been deploying the CHOSEN BRICK malware family to surveil and target dissidents, activists, and journalists across the UK, US, and the Netherlands. The operation is characterized by highly tailored social engineering, often leveraging messaging platforms like WhatsApp and Telegram to build rapport before distributing malicious payloads disguised as legitimate software or documents. Once installed, CHOSEN BRICK provides operators with extensive surveillance capabilities, including audio interception, screen capturing, and the exfiltration of sensitive communications. The actors often target corporate or work-related devices initially, transitioning to personal hardware if detection risks rise. Collected data has previously been published on pro-Iranian leak sites to harass victims.

## Attack Chain

1. Initial contact is established via messaging platforms (WhatsApp, Telegram) using persona-driven social engineering (T1566.003).
2. The target is convinced to download a malicious file masquerading as legitimate software (e.g., Norton Antivirus, KeePass) or document types (e.g., MRI scan results) (T1204.002).
3. Upon execution, the malware establishes persistence by creating an entry in the HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run registry key (T1547.001).
4. The malware attempts to evade detection by modifying Microsoft Defender configuration to add specific folder or file exclusions (T1685).
5. The malware connects to a unique Telegram bot ID associated with the specific victim for command and control (T1102.002).
6. The actor executes discovery and collection tasks, such as process enumeration, screen capture (T1113), or microphone activation (T1123).
7. Data exfiltration occurs via the Telegram C2 channel or direct uploads to cloud object stores like VultrObjects and StorjShare (T1567.002).
8. If directed, the malware can download secondary payloads or perform destructive actions such as file or system wiping (T1485).

## Impact

The impact of CHOSEN BRICK includes the unauthorized collection of sensitive personal data, monitoring of movements and communications, and the potential for severe physical safety risks. Victims have been subjected to harassment via the publication of stolen private details on public websites. The targeting of activists and journalists specifically undermines the privacy and security of individuals opposing the Iranian regime.

## Recommendation

* Run the PowerShell command 'reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run' to inspect for unrecognized persistence mechanisms.
* Monitor DNS and proxy logs for connections to command-and-control and exfiltration domains including api.telegram.org, backblazeb2.com, vultrobjects.com, storjshare.io, iproyal.com, and lightningproxies.net.
* Deploy endpoint security monitoring to detect modifications to Microsoft Defender exclusions (T1685).
* Educate high-risk personnel on social engineering lures distributed via messaging applications, particularly those purporting to be technical support.
* Verify that corporate and personal devices are regularly audited for suspicious files, particularly in non-standard directories like 'C:\Windows \SysWOW64' (note the space in the folder name).
