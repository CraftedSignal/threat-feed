---
title: PanDa Android RAT Campaign Targeting Mexican Financial Users
slug: 2026-09-panda-rat
description: Chinese-speaking threat actors are using the AppPanda phishing platform to distribute the PanDa Android RAT via Meta Ads, targeting Spanish-speaking users in Mexico to harvest banking credentials.
date: "2026-09-02T00:07:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mobile
  - rat
  - phishing
  - android
  - malware
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Intel 471 Malware Intelligence researchers recently uncovered a sprawling phishing operation that used Meta Ads to distribute a newly identified Android remote access trojan (RAT) targeting Spanish-speaking users in Mexico.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: Upon launch of the loader application, the user is asked to toggle system settings to enable installs outside of the official Google Play store — allegedly to enjoy smooth playback in the fake Netflix app.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Once privileges are granted, the application shows a loading page while the malicious payload initializes in the background.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1497
    technique_name: Virtualization/Sandbox Evasion
    evidence: The actors employed numerous tricks to ensure victims install PanDa payload... Before installing, it randomizes part of that APK's signature so every install produces a unique file, defeating simple blocklist/hash-based detection.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
    evidence: This sophisticated spyware... provides extensive surveillance to spy on the victim and collect sensitive data, including screen streaming...
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1056
    technique_name: Input Capture
    evidence: We intercepted a list of applications targeted with the keylogging module, which abuses Android accessibility services to steal the secrets entered by victims.
    confidence_band: high
references:
  - https://www.intel471.com/blog/chinese-speaking-threat-actors-targeting-mexican-android-users-with-remote-access-trojan
iocs:
  - type: domain
    value: alvoplay.com
  - type: domain
    value: celoloplay.com
  - type: domain
    value: cineviabox.com
  - type: domain
    value: evotiprime.com
  - type: domain
    value: farorelive.com
  - type: domain
    value: halogobox.com
  - type: domain
    value: halonanow.com
  - type: domain
    value: novaoraprime.com
  - type: domain
    value: picomiplay.com
  - type: domain
    value: rivasatv.com
  - type: domain
    value: ultratv.com
  - type: domain
    value: vivaplay.com
ioc_counts:
  domain: 12
action_plan:
  priority: elevated
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Block identified phishing domains at the DNS level.
      owner: SOC
      due: 24h
      evidence: Domains provided in IOC table.
  hunt_leads:
    - lead: Identify Android devices within the network performing unauthorized external connections to suspicious streaming domains.
      technique_id: T1566.003
      data_needed:
        - DNS query logs
        - Proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: PanDa RAT uses WebSocket connections for C2.
  mitigation_plan:
    - priority: immediate
      action: Enable MDM policies to block 'Install from Unknown Sources' on corporate mobile devices.
      owner: IT Operations
      addresses: Android platform infection vector
      evidence: Source document describes this as the primary method of delivery for the secondary RAT payload.
---

Intel 471 has identified a coordinated, large-scale phishing operation utilizing a management platform dubbed AppPanda to distribute the PanDa Android remote access trojan (RAT). Since May 2026, the campaign has targeted Spanish-speaking users in Mexico through Meta Ads, masquerading as legitimate streaming services such as Netflix, NovaFlix, and various fictitious brands. The infrastructure supports an as-a-service model, allowing affiliates to generate malicious APK payloads via an 'APK Factory' and manage ad attribution through 'Appchi'. PanDa is a sophisticated spyware capable of screen streaming, hidden virtual network computing (HVNC), keylogging, and remote device control. By abusing Android accessibility services, the malware targets credentials from over 62 banking and financial institutions in Mexico and Nigeria. The operation is highly scalable, with one week of activity in July 2026 resulting in nearly 15,000 malicious app downloads.

## Attack Chain

1. Attacker creates malicious Meta Ads impersonating popular streaming services to attract Mexican mobile users.
2. Victim clicks the advertisement, resolving to a 'jump domain' that redirects to an AppPanda-managed phishing site.
3. Victim downloads a malicious APK file, tracked as the 'ShellA' loader, masquerading as a streaming application.
4. The loader prompts the victim to enable 'install from unknown sources' in system settings to facilitate the secondary payload installation.
5. ShellA decrypts hidden files, randomizes its internal signature to evade hash-based detection, and installs the final PanDa RAT APK.
6. PanDa launches and requests 'accessibility services' permissions, which the attacker abuses to capture credentials and monitor sensitive interactions.
7. The malware establishes a non-encrypted WebSocket connection to the command-and-control (C2) server for data exfiltration and remote command reception.
8. The attacker uses the C2 to remotely control the device, perform keylogging, or stream the screen to harvest financial login information.

## Impact

The PanDa campaign poses a significant threat to mobile banking customers, with documented targeting of 62 financial institutions. The successful deployment of the RAT grants attackers full surveillance capabilities, including the ability to bypass typical security controls via HVNC and accessibility service abuse. The scale of the operation - over 350,000 landing page visits and 15,000 downloads in a single week - indicates a persistent and highly effective threat to the financial sector in the targeted regions.

## Recommendation

Prioritize the following actions to detect and mitigate the AppPanda operation:
- Block the documented phishing domains at the enterprise DNS resolver or proxy layer.
- Implement mobile device management (MDM) policies to restrict the installation of applications from unknown sources on corporate-managed devices.
- Monitor for unusual WebSocket traffic patterns originating from mobile endpoints to unknown or suspicious IP ranges.
- Review network logs for outbound traffic to the phishing domains identified in the IOC table.
- Conduct user awareness training specifically targeting 'malvertising' and suspicious streaming app promotions on social media platforms.
