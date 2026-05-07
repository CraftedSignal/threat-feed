---
title: HackingTeam RCS Implant Installer Analysis
slug: 2016-02-hackingteam-rcs
description: An implant installer for HackingTeam's RCS implant uses Apple's native OS X encryption scheme and a custom packer to deliver a persistent implant, indicating a potential resurgence of the group and an evolution in their techniques for macOS malware.
date: "2016-02-26T07:47:15Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - HackingTeam
tags:
  - hackingteam
  - rcs
  - malware
  - macos
vendors:
  - Apple
products:
  - macOS
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
references:
  - https://objective-see.org/blog/blog_0x0D.html
iocs:
  - type: hash_sha256
    value: 58e4e4853c6cfbb43afd49e5238046596ee5b78eca439c7d76bd95a34115a273
  - type: hash_sha256
    value: 14f4a490be8e4f4aaf672c7e0db8f5bfdda0bbcf78031f5db543879f40156d19
  - type: domain
    value: objective-see.com
ioc_counts:
  domain: 1
  hash_sha256: 2
rules:
  - title: Detect HackingTeam RCS Implant Launch Agent Creation
    description: Detects the creation of the Launch Agent plist file associated with the HackingTeam RCS implant.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1543.001
    data_sources:
      - file_event
      - macos
  - title: Detect HackingTeam RCS Implant File Creation
    description: Detects the creation of the implant executable.
    platform: sigma
    severity: high
    tactics:
      - installation
    techniques:
      - T1566
    data_sources:
      - file_event
      - macos
rules_count: 2
---

The Objective-See blog post from February 2016 analyzes an implant installer believed to be associated with HackingTeam's Remote Control System (RCS) implant. The analysis reveals that this installer employs Apple's native OS X encryption scheme and a custom packer, a notable shift in tactics. The sample, available on VirusTotal, was initially undetected by AV vendors. This suggests a potential resurgence of HackingTeam and an effort to evade traditional detection methods. The use of encryption and packing highlights the need for advanced analysis techniques and tools to uncover the malicious payload. The installer drops and executes a persistent implant, along with an encrypted configuration file. This activity indicates a sophisticated attempt to maintain long-term access to the compromised system.

## Attack Chain

1. The attacker deploys the encrypted HackingTeam RCS implant installer to the target macOS system.
2. The installer uses Apple's native OS X encryption scheme to protect the binary.
3. The installer decrypts itself using a static Blowfish key.
4. The decrypted installer unpacks itself from a custom packer.
5. The unpacked installer drops a persistent implant to `~/Library/Preferences/8pHbqThW/_9g4cBUb.psr`.
6. The installer drops an encrypted data file to `~/Library/Preferences/8pHbqThW/Bs-V7qIU.cYL`.
7. The installer executes the dropped implant using `execve`.
8. The persistent implant installs itself as a user Launch Agent with the name `com.apple.FinderExtAvt.plist`, ensuring persistence upon reboot.

## Impact

A successful infection leads to the installation of the HackingTeam RCS implant on the macOS system. This allows the attackers to remotely control the system, potentially exfiltrate sensitive data, monitor user activity, and install additional malicious software. The use of encryption and packing significantly hinders detection and analysis, potentially allowing the implant to remain undetected for an extended period. While the number of victims is not specified, the use of sophisticated techniques suggests targeted attacks against high-value individuals or organizations.

## Recommendation

*   Monitor file creation events for the creation of files in `~/Library/Preferences/8pHbqThW/` to detect potential RCS implant activity.
*   Deploy the Sigma rule to detect the creation of the LaunchAgent file associated with the RCS implant.
*   Block the listed IOCs, specifically the SHA256 hashes of the implant installer and persistent implant, at the endpoint to prevent execution.
*   Utilize tools like Objective-See's BlockBlock and KnockKnock to detect and block persistence attempts and enumerate installed binaries.
