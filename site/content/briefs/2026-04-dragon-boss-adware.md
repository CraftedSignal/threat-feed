---
title: Dragon Boss Solutions Adware Disabling Antivirus Protections
slug: 2026-04-dragon-boss-adware
description: Digitally signed adware from Dragon Boss Solutions LLC deploys payloads with SYSTEM privileges to disable antivirus protections on thousands of endpoints across education, utilities, government, and healthcare sectors.
date: "2026-04-16T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - adware
  - antivirus-evasion
  - malware
  - windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1053
    technique_name: Scheduled Task/Job
references:
  - https://www.bleepingcomputer.com/news/security/signed-software-abused-to-deploy-antivirus-killing-scripts/
iocs:
  - type: domain
    value: chromsterabrowser[.]com
  - type: domain
    value: worldwidewebframework3[.]com
ioc_counts:
  domain: 2
rules:
  - title: Detect ClockRemoval.ps1 PowerShell Script Execution
    description: Detects the execution of the ClockRemoval.ps1 PowerShell script used to disable antivirus products.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Hosts File Modification Blocking AV Domains
    description: Detects modification of the hosts file to block antivirus vendor domains.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A digitally signed adware tool distributed by Dragon Boss Solutions LLC has been observed deploying payloads designed to disable antivirus protections. The campaign, discovered by Huntress on March 22, 2026, leverages signed executables initially classified as potentially unwanted programs (PUPs) to gain a foothold on victim machines. These PUPs, often disguised as browser tools like Chromstera Browser, Chromnius, WorldWideWeb, Web Genius, and Artificius Browser, use an advanced update mechanism to deliver malicious payloads. This update mechanism, powered by the commercial Advanced Installer, silently deploys MSI and PowerShell scripts with elevated SYSTEM privileges. This allows the threat actors to disable or remove antivirus software without user interaction. The campaign has impacted over 23,500 hosts across 124 countries, including high-value networks in the educational, utilities, government, and healthcare sectors.

## Attack Chain

1.  Initial infection occurs via the installation of signed adware tools (PUPs) from Dragon Boss Solutions LLC, such as Chromnius or WorldWideWeb.
2.  The adware uses the Advanced Installer update mechanism to silently download and execute an MSI payload (Setup.msi) disguised as a GIF image.
3.  The MSI payload is executed with SYSTEM privileges, allowing it to bypass user account control (UAC) restrictions.
4.  The MSI installer performs reconnaissance, checking admin status, detecting virtual machines, verifying internet connectivity, and identifying installed antivirus products from Malwarebytes, Kaspersky, McAfee, and ESET.
5.  A PowerShell script (ClockRemoval.ps1) is deployed to disable the detected security products by stopping services, killing processes, deleting installation directories and registry entries, silently running vendors' uninstallers, and forcefully deleting files.
6.  The ClockRemoval.ps1 script is scheduled to run at system boot, logon, and every 30 minutes to ensure persistent removal of antivirus products.
7.  The hosts file is modified to block access to antivirus vendor domains, preventing reinstallation or updates of the security software.
8.  With antivirus protections disabled, the compromised system becomes vulnerable to further exploitation and malware deployment.

## Impact

This campaign has impacted over 23,500 hosts across 124 countries. Identified infected hosts include 221 academic institutions, 41 operational technology networks, 35 municipal governments and public utilities, 24 primary and secondary educational institutions, and 3 healthcare organizations. The disabling of antivirus software leaves systems vulnerable to further malware infections, data breaches, and other malicious activities. The potential exists for threat actors to leverage this established infrastructure to deploy far more dangerous payloads.

## Recommendation

*   Deploy the Sigma rule detecting the ClockRemoval.ps1 script execution to your SIEM to identify affected systems.
*   Monitor for WMI event subscriptions containing "MbRemoval" or "MbSetup," scheduled tasks referencing "WMILoad" or "ClockRemoval," and processes signed by Dragon Boss Solutions LLC, as recommended by Huntress.
*   Review the hosts file for entries blocking AV vendor domains and check Microsoft Defender exclusions for suspicious paths such as "DGoogle," "EMicrosoft," or "DDapps."
*   Block the C2 domains chromsterabrowser[.]com and worldwidewebframework3[.]com at the DNS resolver.
*   Investigate systems that have downloaded the Setup.msi payload, identified by its hash.
