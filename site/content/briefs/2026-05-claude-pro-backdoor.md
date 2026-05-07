---
title: Fake Claude AI Site Spreads Beagle Backdoor via DLL Sideloading
slug: 2026-05-claude-pro-backdoor
description: A malicious website impersonating Anthropic's Claude AI platform delivers the Beagle backdoor through a DLL sideloading attack, leveraging a compromised G DATA antivirus updater to execute malicious code.
date: "2026-05-07T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - malvertising
  - dll sideloading
  - backdoor
  - beagle
  - donutloader
vendors:
  - Anthropic
  - G DATA
  - Microsoft
products:
  - Claude
  - G DATA antivirus products
  - Microsoft Defender
affected_os:
  - windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1574
    technique_name: Hijack Execution Flow
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.sophos.com/en-us/blog/donuts-and-beagles-fake-claude-site-spreads-backdoor
iocs:
  - type: domain
    value: claude-pro[.]com
  - type: domain
    value: vertextrust-advisors[.]com
  - type: domain
    value: license[.]claude-pro[.]com
ioc_counts:
  domain: 3
rules:
  - title: Detect Suspicious DLL Sideloading with G DATA Updater
    description: Detects DLL sideloading attempts by the G DATA updater (NOVupdate.exe) by monitoring for the loading of avk.dll from the same directory.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1574.002
    data_sources:
      - image_load
      - windows
  - title: Detect Beagle Backdoor Connection
    description: Detects network connections to the Beagle C2 server
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

A fake website mimicking Anthropic's Claude AI platform (claude-pro[.]com) is distributing malware via malvertising. The site offers a "Claude-Pro Relay" download, which is a large ZIP archive containing a malicious MSI installer. The installer drops a trojanized version of the G DATA antivirus updater (NOVupdate.exe), a malicious DLL (avk.dll), and an encrypted data file into the user's startup folder. This leverages DLL sideloading to execute a previously undocumented backdoor, dubbed "Beagle." The attack shares characteristics with PlugX campaigns but utilizes distinct malware components. The threat actor may have inadvertently disclosed their CloudFlare origin certificate, indicating a possible hosting server (209[.]189[.]190[.]206), and are also linked to the domain vertextrust-advisors[.]com (178[.]128[.]108[.]89), registered in mid-April 2026, posing as a legal advisory service.

## Attack Chain

1.  The user clicks on a malvertisement, leading them to the malicious claude-pro[.]com website.
2.  The user downloads the "Claude-Pro Relay" software, a ZIP archive named Claude-Pro-windows-x64.zip.
3.  The user extracts and executes the Claude.msi installer.
4.  The installer drops NOVupdate.exe (a legitimate, signed G DATA updater), avk.dll (a malicious DLL), and NOVupdate.exe.dat (an encrypted data file) into the user's startup folder.
5.  Upon system startup, NOVupdate.exe executes and attempts to load avk.dll from the same directory, sideloading the malicious DLL instead of the legitimate one.
6.  The malicious avk.dll decrypts and executes DonutLoader shellcode from NOVupdate.exe.dat.
7.  DonutLoader loads the Beagle backdoor into memory.
8.  Beagle establishes a connection with its command-and-control server (license[.]claude-pro[.]com) over TCP (443) and/or UDP (8080), awaiting further instructions.

## Impact

Successful execution of this attack leads to the installation of the Beagle backdoor on the victim's system, allowing the attacker to perform various malicious activities, including data theft, remote control, and further malware deployment. The use of a signed G DATA executable for DLL sideloading allows the attackers to bypass some security measures, potentially impacting systems even with antivirus solutions installed. While the exact number of victims is unknown, this campaign leverages widespread malvertising, suggesting a broad potential impact.

## Recommendation

*   Block the malicious domains and IPs associated with this campaign (claude-pro[.]com, vertextrust-advisors[.]com, license[.]claude-pro[.]com, 209[.]189[.]190[.]206, 178[.]128[.]108[.]89, 8[.]217[.]190[.]58) at the DNS resolver and firewall.
*   Deploy the Sigma rule "Detect Suspicious DLL Sideloading with G DATA Updater" to detect the execution of the malicious avk.dll.
*   Monitor process creation events for NOVupdate.exe loading unexpected DLLs using process_creation logs.
*   Investigate systems where files named avk.dll, NOVupdate.exe, and NOVupdate.exe.dat are found together in the same directory, especially within startup folders.
