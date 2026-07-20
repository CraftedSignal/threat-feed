---
title: LG Monitors Auto-Install Adware-Like App on Windows PCs
slug: 2026-07-lg-monitor-adware-installer
description: Connecting certain LG monitors to Windows PCs triggers Windows Update to automatically install the 'LG Monitor App Installer' without user consent, which then runs at system startup and frequently displays advertisements for McAfee antivirus trials.
date: "2026-07-20T14:49:16Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - unwanted-software
  - adware
  - privacy-violation
  - windows
  - lg
vendors:
  - LG
products:
  - LG Monitor App Installer
  - LG UltraGear 34GX900A-B
  - LG UltraFine 32UN880-B
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Once installed, the application registers itself to run when Windows starts.
    confidence_band: high
references:
  - https://hackread.com/lg-monitors-install-adware-app-windows-pcs/
---

LG monitors are automatically installing an adware-like application on Windows PCs, raising significant privacy and cybersecurity concerns. Upon connecting certain LG monitors, Windows Update initiates the download and installation of the "LG Monitor App Installer" from the Microsoft Store, bypassing explicit user consent. This application then registers itself to run persistently at system startup, frequently displaying unsolicited advertisements for McAfee antivirus trials. The app is noted to leverage "runFullTrust" permissions, allowing it to operate outside the standard Windows AppContainer sandbox, further increasing potential security implications. Reports of this behavior, affecting models such as the LG UltraGear 34GX900A-B and LG UltraFine 32UN880-B, date back to at least 2024, with a recent surge in McAfee promotional pop-ups.

## Attack Chain

1. A user connects a compatible LG monitor (e.g., LG UltraGear 34GX900A-B or LG UltraFine 32UN880-B) to a Windows PC.
2. The Windows operating system detects the newly connected hardware and retrieves associated device metadata.
3. Windows Update automatically retrieves associated LG extension and software component packages from Microsoft.
4. The "LG Monitor App Installer" application is then installed from the Microsoft Store without an explicit user approval prompt.
5. The newly installed application registers itself to launch automatically when Windows starts.
6. Upon subsequent system reboots, the application initiates and displays unsolicited promotional pop-up messages, primarily advertising McAfee antivirus trials.
7. The application operates with "runFullTrust" permissions, granting it capabilities beyond the typical restricted Windows AppContainer sandbox.

## Impact

This behavior results in unwanted software installation and persistent, unsolicited advertising on user systems, effectively functioning as adware. Users connecting affected LG monitors, including older models like the LG UltraFine 32UN880-B, are impacted across various sectors. The installation occurs without explicit consent, leading to a degradation of user experience, potential consumption of system resources, and privacy concerns due to an unapproved "full-trust" application running persistently. While there is no evidence of data theft or administrative privilege escalation, the unconsented installation and persistent advertising undermine user control over their computing environment.

## Recommendation

* Remove the "LG Monitor App Installer" via Windows Settings > Apps & Features to uninstall the unwanted application.
* Disable any remaining LG-related entries under Windows Settings > Startup Apps to prevent persistent execution.
* For Windows Pro and Enterprise users, enable the Group Policy setting "Prevent automatic download of applications associated with device metadata" located under Computer Configuration > Administrative Templates > System > Device Installation to block similar future installations.
