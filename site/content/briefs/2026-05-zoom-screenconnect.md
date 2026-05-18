---
title: Zoom-themed Phishing Campaign Delivering ConnectWise ScreenConnect
slug: 2026-05-zoom-screenconnect
description: A phishing campaign impersonates Zoom to trick users into downloading and installing ConnectWise ScreenConnect, a legitimate remote monitoring and management tool, allowing attackers to gain persistent remote access, harvest credentials, and deploy secondary malware such as ransomware.
date: "2026-05-18T12:47:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - remote_access
  - social_engineering
  - screenconnect
  - zoom
vendors:
  - Zoom
  - ConnectWise
  - Microsoft
products:
  - Zoom
  - ConnectWise ScreenConnect
  - Windows Script Host
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1218
    technique_name: System Binary Proxy Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://cofense.com/blog/click-install-compromised-the-new-wave-of-zoom-themed-attacks
iocs:
  - type: domain
    value: nasbv[.]site
  - type: hash_md5
    value: B677CEAABB0BE3911D1D3C80B1F84899
  - type: hash_sha256
    value: 90247B84E192A582C5AF8BC75C3A7611CC9621B4683A7CCB68901F4F22503E00
  - type: hash_md5
    value: 9562334dd9a47ec1239a8667ddc1f01c
ioc_counts:
  domain: 1
  hash_md5: 2
  hash_sha256: 1
rules:
  - title: Detect Suspicious VBScript Downloading MSI
    description: Detects VBScript execution that downloads an MSI installer, a common technique used in this Zoom-themed ScreenConnect campaign.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
  - title: Detect ScreenConnect Installation via VBScript
    description: Detects ScreenConnect installation initiated by a VBScript, indicating potential malicious activity related to the Zoom-themed campaign.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - remote_access
    techniques:
      - T1218.005
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This phishing campaign leverages social engineering techniques using the Zoom platform as a lure to trick users into installing ConnectWise ScreenConnect, a legitimate remote monitoring and management (RMM) tool. Attackers send emails impersonating Zoom meeting invitations. These emails redirect victims to fake Zoom-branded landing pages that use audio playback and fraudulent software update prompts to persuade victims to download and execute a disguised VBS installer. This installer silently downloads and launches the ScreenConnect payload, granting attackers persistent remote access to compromised systems. The attackers abuse trusted platforms and legitimate administrative tools to blend malicious activity into normal enterprise behavior, enabling credential theft, reconnaissance, lateral movement, and potential ransomware deployment.

## Attack Chain

1.  The victim receives a phishing email impersonating a Zoom meeting invitation, containing a hyperlink to a spoofed Zoom-branded landing page.
2.  Upon clicking the link, the victim is redirected to a fake Zoom meeting page designed to mimic a legitimate Zoom interface.
3.  The fake meeting page plays a distorted audio track to simulate a real meeting environment and requests microphone access.
4.  After a few seconds, a popup appears, falsely notifying the user that a Zoom update is available and automatically downloaded.
5.  The victim is redirected to a separate page with instructions to run the downloaded "update", a VBS file named "_zoommeeting_Zoom_installer_64_bit.exe.vbs".
6.  The VBS file, when executed via Windows Script Host, downloads the ScreenConnect installer (ScreenConnect.ClientSetup.msi) from a hardcoded URL (212[.]11[.]64[.]45) to the user's %TEMP% directory.
7.  The ScreenConnect installer is launched in a hidden window, installing the remote access tool on the victim's system.
8.  Attackers leverage ScreenConnect for credential theft, internal reconnaissance, lateral movement, and potential deployment of secondary payloads, such as ransomware.

## Impact

Successful exploitation leads to the installation of ConnectWise ScreenConnect, granting attackers persistent remote access to the victim's system. This access allows attackers to perform credential theft, internal reconnaissance, lateral movement within the network, and the potential deployment of secondary payloads, such as ransomware. The use of a legitimate RMM tool like ScreenConnect allows attackers to blend malicious activity with expected enterprise administration behavior, making detection more difficult.

## Recommendation

*   Block the malicious domains and IP addresses associated with the phishing campaign at the network level to prevent initial access (IOC table: `nasbv[.]site`, `104[.]21[.]56[.]35`, `172[.]67[.]176[.]105`, `212[.]11[.]64[.]45`).
*   Implement endpoint detection rules to identify the execution of VBS scripts downloading and launching MSI installers from unusual locations like the %TEMP% directory (see Sigma rule: "Detect Suspicious VBScript Downloading MSI").
*   Monitor for the installation and execution of ConnectWise ScreenConnect from unexpected sources, specifically when initiated by a VBScript process (see Sigma rule: "Detect ScreenConnect Installation via VBScript").
*   Implement application control policies to restrict the execution of VBScripts from the %TEMP% directory to prevent the execution of the malicious downloader.
*   Educate users about the risks of social engineering attacks and the importance of verifying software update prompts, especially those delivered through web pages.
