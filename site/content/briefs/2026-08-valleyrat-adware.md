---
title: ValleyRAT Backdoor Distributed via Masqueraded Adware Installers
slug: 2026-08-valleyrat-adware
description: Threat actors are distributing the ValleyRAT backdoor by masquerading it as legitimate software and adware, utilizing DLL sideloading and registry-based defense evasion.
date: "2026-08-31T11:55:05Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - backdoor
  - malware
  - dll-sideloading
  - defense-evasion
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574.002
    technique_name: DLL Side-Loading
    evidence: In this case, however, the attackers use it to carry out DLL sideloading, a technique that allows malicious code to run under the guise of a signed process by way of a malicious DLL.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: Registry Run Keys / Startup Folder
    evidence: Regardless of the file name, the installer deploys a modified Chinese desktop wallpaper management tool called QN Wallpaper... and adds it to the registry's autorun entries.
    confidence_band: high
references:
  - https://securelist.com/valleyrat-backdoor-adware/121175/
iocs:
  - type: hash_md5
    value: c24e99f9437feacaa63766a3cde3fe3d
  - type: hash_md5
    value: 07ddbbe2c71c45577a7a4fbcdba0df91
  - type: hash_md5
    value: 48826d5ca845979d2e6ebd66dc1aae90
ioc_counts:
  hash_md5: 3
rules:
  - title: Detect ValleyRAT DLL Sideloading via libcef.dll
    description: Detects the loading of a suspicious libcef.dll file from within the QNWallpaper directory, a known indicator of ValleyRAT sideloading.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1574.002
    data_sources:
      - image_load
      - windows
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block MD5 hashes listed in IOC table
      owner: SOC
      due: 24h
      evidence: Confirmed malicious installer and backdoor components
  mitigation_plan:
    - priority: immediate
      action: Remove unauthorized QN Wallpaper installations
      owner: IT Operations
      addresses: T1574.002
      evidence: Malicious software identified as QN Wallpaper wrapper
---

Threat actors are actively distributing the ValleyRAT backdoor by masquerading as potentially unwanted programs and legitimate adware. The delivery mechanism utilizes malicious installers that appear to deploy common applications like Google Chrome or DingTalk, but actually deploy a modified version of the QN Wallpaper management utility. The infection chain relies on DLL sideloading, where a malicious version of 'libcef.dll' is used to execute the ValleyRAT payload when the legitimate QN Wallpaper executable is launched. To facilitate persistence and hinder detection, the installer modifies registry keys to disable Windows Defender and establishes autorun entries. The campaign is notable for its abuse of signed software distribution models and the deliberate attempt to leverage the trust users place in adware exclusions to prevent security tooling from flagging the malicious activity.

## Attack Chain

1. The user executes a malicious installer (e.g., FS_SETUP_DD_173.exe) disguised as a legitimate application.
2. The installer modifies the Windows registry to disable Windows Defender via the 'DisableAntiSpyware' key.
3. The installer unpacks the QN Wallpaper suite, including a malicious 'libcef.dll' and encrypted backdoor component 'PeLoader', into 'C:\Program Files\QNWallpaper\5.4.0.1662\' plus a random suffix.
4. The installer sets autorun registry keys to ensure persistence of the QN Wallpaper application across reboots.
5. The installer launches 'QnWallpaper.exe', triggering the side-loading of the malicious 'libcef.dll'.
6. The 'libcef.dll' library executes its malicious code via 'DllMain' or a latent 'RunDLL' export upon initialization.
7. The backdoor initiates communication with its command-and-control infrastructure to establish persistent remote access.

## Impact

Successful execution results in the deployment of the ValleyRAT backdoor, providing attackers with remote access and control over the compromised system. This allows for potential exfiltration of sensitive information, further malware installation, and long-term persistence in corporate or personal environments.

## Recommendation

* Deploy the provided Sigma rules to detect DLL sideloading from non-standard application paths.
* Monitor for registry modifications targeting 'DisableAntiSpyware' and 'Run' keys using EDR or Sysmon.
* Implement blocklists for the known malicious file hashes in the IOC table across all endpoints.
* Restrict the ability of non-administrative users to modify registry keys associated with security features.
* Audit 'C:\Program Files\QNWallpaper\' and similar paths for files with suspicious hashes or unexpected DLL files.
