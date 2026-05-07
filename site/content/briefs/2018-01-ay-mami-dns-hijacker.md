---
title: OSX/MaMi DNS Hijacking Malware
slug: 2018-01-ay-mami-dns-hijacker
description: OSX/MaMi is a macOS malware that hijacks DNS settings and installs a malicious certificate into the system keychain to intercept network traffic, while also possessing capabilities for taking screenshots, simulating mouse events, persisting as a launch item, downloading and uploading files, and executing commands.
date: "2018-01-11T07:33:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - dns hijacking
  - macos
  - mami
  - malware
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1556
    technique_name: Modify Authentication Process
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://objective-see.org/blog/blog_0x26.html
iocs:
  - type: url
    value: http://regardens.info/
  - type: ip
    value: 82.163.143.135
  - type: ip
    value: 82.163.142.137
  - type: domain
    value: honouncil.info
  - type: domain
    value: gorensin.info
  - type: domain
    value: squartera.info
ioc_counts:
  domain: 3
  ip: 2
  url: 1
rules:
  - title: Detect DNS Server Modification via Network Configuration
    description: Detects modification of DNS server settings by monitoring network configuration changes.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1556.002
    data_sources:
      - process_creation
      - macos
  - title: Detect Network Connection to MaMi Reporting Domains
    description: Detects network connections to domains used by MaMi for reporting activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - macos
rules_count: 2
---

OSX/MaMi, a macOS malware identified in January 2018, targets users by hijacking their DNS settings and installing a malicious certificate into the System keychain. This allows attackers to potentially intercept all network traffic. The malware, version 1.1.0, exhibits a range of functionalities beyond DNS hijacking, including the ability to take screenshots, generate simulated mouse events, persist as a launch item, download and upload files, and execute arbitrary commands. This malware communicates with various domains such as honouncil.info, gorensin.info and squartera.info to report activity, posing a significant risk to user privacy and data security.

## Attack Chain

1.  The malware is initially downloaded from a hosting site, such as `http://regardens.info/`.
2.  The downloaded Mach-O executable is executed on the macOS system.
3.  MaMi modifies the system's DNS settings, replacing the legitimate DNS servers with malicious ones, specifically `82.163.143.135` and `82.163.142.137`.
4.  The malware installs a malicious certificate into the System keychain, likely using `security add-trusted-cert` command to bypass certificate pinning.
5.  It may establish persistence by configuring itself as a launch item using `programArguments` and `runAtLoad` methods.
6.  MaMi takes screenshots of the user's desktop using the `takeScreenshotAt:` method.
7.  The malware exfiltrates collected data and sends reports to command and control servers, including `honouncil.info`, `gorensin.info`, and `squartera.info` over HTTP.
8.  The attacker gains complete control over the victim's network traffic.

## Impact

Successful exploitation allows attackers to intercept network traffic, potentially stealing sensitive information like usernames, passwords, and financial data. Victims may experience redirection to malicious websites, phishing attacks, or installation of further malware. The malware also has the ability to take screenshots and simulate mouse clicks, potentially granting attackers access to sensitive data displayed on the screen or enabling them to perform actions on the infected system remotely.

## Recommendation

*   Monitor network traffic for DNS queries directed to the malicious DNS servers `82.163.143.135` and `82.163.142.137`.
*   Monitor for outbound network connections to the reporting domains `honouncil.info`, `gorensin.info`, and `squartera.info` using network_connection category rules.
*   Implement the provided Sigma rules to detect suspicious processes modifying DNS settings or installing certificates.
*   Monitor process creations for execution of unsigned Mach-O binaries.
