---
title: ValleyRAT Backdoor Distributed via Signed Adware
slug: 2026-08-valleyrat-adware
description: The threat actor Silver Fox is distributing the ValleyRAT backdoor disguised as a signed QN Wallpaper adware application to leverage user-applied antivirus exclusions.
date: "2026-08-31T12:55:01Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Silver Fox
tags:
  - backdoor
  - malware
  - dll-sideloading
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574.002
    technique_name: DLL Side-Loading
    evidence: The disguise relies on DLL sideloading.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1112
    technique_name: Modify Registry
    evidence: The installer unpacks a modified copy of QN Wallpaper and runs its signed executable... The installer switches off Windows Defender through the DisableAntiSpyware registry key.
    confidence_band: high
references:
  - https://thehackernews.com/2026/08/valleyrat-backdoor-hides-in-signed.html
iocs:
  - type: hash_md5
    value: c24e99f9437feacaa63766a3cde3fe3d
  - type: hash_md5
    value: 07ddbbe2c71c45577a7a4fbcdba0df91
  - type: hash_md5
    value: 8a626d844943da3456b044f38deae3a2
  - type: ip
    value: 103.45.66.18
  - type: ip
    value: 192.253.225.173
  - type: domain
    value: qnwallpaper.keansoft.cn
ioc_counts:
  domain: 1
  hash_md5: 3
  ip: 2
rules:
  - title: Detect DLL Sideloading via Libcef.dll
    description: Detects potentially malicious libcef.dll loaded by a process that is typically unrelated to Chromium or standard application paths, often used in sideloading
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1574.002
    data_sources:
      - image_load
      - windows
  - title: Detect DisableAntiSpyware Registry Modification
    description: Detects attempts to disable Windows Defender via the DisableAntiSpyware registry key
    platform: sigma
    severity: critical
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - registry_set
      - windows
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block identified C2 IP addresses at perimeter firewall
      owner: SOC
      due: 24h
  hunt_leads:
    - lead: Search for files named libcef.dll outside of standard browser paths
      technique_id: T1574.002
      priority: high
      disposition: hunt_now
---

The threat actor known as Silver Fox has been observed deploying the ValleyRAT backdoor (also identified as Winos 4.0) by embedding it within a modified, signed version of the QN Wallpaper adware application. By leveraging a legitimately signed executable, the attackers trick users into trusting the application and adding the installation directory to antivirus exclusion lists. This activity enables the malware to operate with reduced interference from endpoint security controls. 

The delivery relies on DLL sideloading, where a malicious 'libcef.dll' is planted alongside the legitimate 'QnWallpaper.exe'. Upon execution, the backdoor gains full control over the compromised machine, enabling sensitive data exfiltration - including keystrokes, clipboard contents, and screenshots - as well as the deployment of additional malicious modules. The infection process also attempts to disable Windows Defender and utilizes defensive measures that trigger a system crash if a user attempts to terminate the malicious process. This technique represents a sustained effort by Silver Fox to abuse trust in signed applications for persistent access.

## Attack Chain

1. The user executes the malicious installer, which unpacks the legitimate signed 'QnWallpaper.exe' and the malicious 'libcef.dll' into a common directory.
2. The installer modifies the Windows Registry to set 'DisableAntiSpyware' to 1, attempting to neutralize native security protections.
3. The installer creates a persistent entry in the system autorun registry keys to ensure execution upon boot.
4. The installer checks for current process privileges; if non-administrative, it relaunches itself using 'runas' to obtain elevated system access.
5. The signed 'QnWallpaper.exe' process initiates, which inadvertently loads the malicious 'libcef.dll' present in its working directory (DLL Sideloading).
6. The ValleyRAT payload initiates, connects to C2 infrastructure, and monitors for active termination attempts, triggering a system crash if the process is closed.
7. The backdoor enables remote control, allowing the attacker to perform keystroke logging, clipboard harvesting, and data exfiltration.

## Impact

The campaign leverages trusted software to gain persistent, elevated access to victim systems. Successfully compromised machines are fully controlled by the threat actor, allowing for the collection of sensitive PII, passwords, and proprietary data. While the specific impact per organization varies, ValleyRAT has been detected in over 1,500 unique environments throughout 2026, primarily affecting users in China and India.

## Recommendation

Prioritize the implementation of the following detections and defensive controls:
- Deploy the Sigma rules below to monitor for suspicious DLL loads by signed processes and unauthorized registry modifications.
- Audit existing antivirus and EDR exclusion lists to identify and remove entries pointing to 'C:\Program Files\QNWallpaper\' or other suspicious adware locations.
- Restrict the ability of users to add security product exclusions, enforcing these policies via Group Policy or centralized management consoles.
- Block communication to the identified C2 IP addresses (103.45.66.18, 192.253.225.173) at the perimeter firewall.
