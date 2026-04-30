---
title: Mirax RAT Targeting Android Users in Europe
slug: 2026-04-mirax-rat
description: Mirax RAT, a new Android RAT distributed as MaaS, is targeting European users by turning infected devices into residential proxy nodes and enabling credential theft via overlay and notification injection.
date: "2026-04-16T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - android
  - rat
  - mirax
  - malware-as-a-service
  - proxy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1621
    technique_name: Multi-Factor Authentication Request Generation
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1113
    technique_name: Screen Capture
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://www.securityweek.com/mirax-rat-targeting-android-users-in-europe/
rules:
  - title: Android App Installation from Unknown Sources
    description: Detects the installation of applications from unknown sources on Android devices, which is a common step in Mirax RAT infections.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - linux
  - title: Suspicious Network Connection from Newly Installed Android App
    description: Detects network connections originating from newly installed Android applications, potentially indicating command and control activity.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The Mirax RAT is a newly identified Android Remote Access Trojan (RAT) that has been actively targeting users in Europe since March 2026. It's offered as Malware-as-a-Service (MaaS) to a small group of affiliates, primarily Russian-speaking actors, through tiered subscription models. Since December 2025, Mirax has been promoted on underground forums and used in multiple campaigns. The RAT's distribution relies on malicious advertisements on Meta platforms like Facebook, Instagram, and Messenger, with over 200,000 users potentially exposed to these ads. The malware uses dropper pages hosted on GitHub and relies on APK sideloading for execution, bypassing the Google Play Store's security measures. Mirax's capabilities extend beyond typical RAT functions, including turning infected devices into residential proxy nodes via a SOCKS5 proxy.

## Attack Chain

1.  The attacker creates malicious ads on Facebook, Instagram, and Messenger promoting IPTV application services.
2.  Users click on the advertisements, which redirect them to dropper pages hosted on GitHub.
3.  The user is prompted to enable installation from unknown sources on their Android device.
4.  The malicious IPTV application is installed via APK sideloading.
5.  The application initiates a multi-stage infection process, utilizing Golden Encryption (Golden Crypt) to pack the payload.
6.  The payload, an encrypted Dalvik Executable (.dex) file, is decrypted during installation using the RC4 stream cipher with a hardcoded key.
7.  Mirax gains control of the device, enabling overlay and notification injection for credential theft.
8.  Attackers can view the screen in real-time, navigate and control the device, manage applications, exfiltrate images and text, and launch a SOCKS5 proxy connection to proxy traffic through the infected device.

## Impact

The Mirax RAT campaign has the potential to affect a large number of Android users in Europe. The malicious advertisements have already reached over 200,000 users. Successful infections can lead to credential theft, financial fraud, data exfiltration, and the compromised device being used as a residential proxy, potentially masking malicious activity and further expanding the attacker's reach. Banks and financial institutions are specifically highlighted as high-value targets.

## Recommendation

*   Monitor network traffic for connections to GitHub domains associated with APK downloads, and correlate that with android device user agents (Network Connection and User Agent logs).
*   Implement detections for process creation events related to sideloaded APK installations, specifically looking for unusual parent-child process relationships (Process Creation Logs).
*   Deploy the Sigma rule provided below to detect the execution of applications from untrusted sources and tune for your environment.
*   Monitor network connections for SOCKS5 proxy traffic originating from Android devices, which may indicate compromised devices acting as residential proxies (Network Connection Logs).
