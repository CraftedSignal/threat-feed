---
title: Midnight Mimosa Pre-installed Malware Campaign
slug: 2026-10-midnight-mimosa
description: The Midnight Mimosa campaign utilizes platform-signed, pre-installed malware on low-cost MediaTek Android devices to execute ad fraud, click fraud, and residential-proxy botnet enrollment.
date: "2026-10-08T13:13:07Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - mobile
  - malware
  - android
  - botnet
  - ad-fraud
  - supply-chain
vendors:
  - MediaTek
products:
  - Android (low-cost hardware)
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: The malware ships preinstalled in the device firmware, and we found multiple system packages involved, depending on the device.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The culprit, com.android.system.lite, is a pre-installed Android system application... ships signed for the platform, runs as the system user.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.001
    technique_name: Disable or Modify Tools
    evidence: The malware disables the Google Play Store app just before installing a payload app (probably attempting to avoid a potential Play Protect detection).
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Web Protocols
    evidence: The system app and payload family use shared infrastructure, including a command-and-control service disguised as a weather API.
    confidence_band: high
references:
  - https://www.bitdefender.com/en-us/blog/labs/midnight-mimosa-malware
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review mobile device fleet for low-cost MediaTek-based hardware and audit installed system packages.
      owner: SOC
      due: 48h
      evidence: The enabler silently deploys a rotating family of at least 32 unique disguised apps.
  hunt_leads:
    - lead: Identify devices with unrecognized system packages like com.android.system.lite or com.android.sys.prot.
      technique_id: T1082
      data_needed:
        - Mobile Device Management (MDM) inventory
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: We identified the same malware core shipping under a rotating set of system-sounding names.
  mitigation_plan:
    - priority: immediate
      action: Isolate devices confirmed to be running persistent system-uid malware.
      owner: IT Operations
      addresses: Persistent malware persistence
      evidence: It is impossible to uninstall; there is no store review, and it is not the user is choice.
---

Midnight Mimosa is an Android malware campaign discovered by Bitdefender, affecting low-cost, multi-brand devices built on MediaTek hardware. The malware is present in the device firmware before the user switches the phone on for the first time. The primary infection vector is a platform-signed system package, such as 'com.android.system.lite', 'com.android.sys.prot', or 'com.android.sys.gmsprot', which runs with system-uid privileges. 

This privileged access allows the malware to silently install and remove applications, grant sensitive permissions, and load arbitrary code via remote DEX plugins. The malware uses a native library (libeasy.so) to decrypt and drop an obfuscated Java framework that manages C2 communication and payload deployment. Beyond pre-installed components, the campaign involves thirteen malicious applications distributed via Google Play that share common C2 infrastructure. The operation generates revenue through ad fraud, click fraud, and by transforming compromised devices into residential-proxy nodes for botnets.

## Attack Chain

1. Factory-level firmware modification embeds a platform-signed, system-uid application (e.g., com.android.system.lite) into the device ROM.
2. Upon boot, the system app initializes and executes a native library (libeasy.so).
3. The native library RC4-decrypts an obfuscated Java framework within the system-uid process.
4. The framework fetches remote configuration from a C2 server masquerading as a weather API.
5. The malware silently installs stage-2 and stage-3 DEX plugins to facilitate monetization.
6. The system-uid process grants itself sensitive permissions (Accessibility, Notification Access) to maintain control and perform background actions.
7. The malware disables the Google Play Store momentarily to install dropper payloads (e.g., com.mobile.applock.wt) and re-enables it afterwards.
8. Payloads execute hidden ad fraud, automated clicking, or initiate residential-proxy relay connections to support DDoS botnets.

## Impact

The campaign affects low-cost Android devices, often marketed as counterfeit flagship models (e.g., S24 Ultra, S25 Ultra). Successful infection grants operators permanent, unremovable system-level access, leading to unauthorized ad revenue generation, potential DDoS participation, and exposure of user data via residential-proxy exploitation. The impact is persistent, as the malware cannot be uninstalled by the end-user.

## Recommendation

Prioritize detection and monitoring of device behavior rather than relying on static file scanning, as the malware is platform-signed and persistent.

- Implement behavioral analysis to detect anomalous system-uid processes that repeatedly enable/disable sensitive permissions like Accessibility or Notification Access.
- Monitor for unauthorized installation of system packages or unexpected background activity involving packages like 'com.android.system.lite' or 'com.android.sys.prot'.
- Conduct network traffic analysis for devices communicating with known weather API-disguised command-and-control servers.
- Restrict the procurement of low-cost, unverified Android hardware in enterprise environments, as firmware integrity cannot be guaranteed.
