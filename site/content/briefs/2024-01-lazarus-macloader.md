---
title: Lazarus Group Macloader Malware Analysis and Repurposing
slug: 2024-01-lazarus-macloader
description: The Lazarus group's macloader malware (OSX.AppleJeus.C) uses a launch daemon for persistence and executes downloaded payloads directly from memory, communicating with a C2 server to retrieve second-stage payloads, posing a significant threat due to its fileless execution and potential for repurposing.
date: "2024-01-03T15:00:00Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - Lazarus Group
  - HIDDEN COBRA
  - LABYRINTH CHOLLIMA
  - Diamond Sleet
  - Zinc
tags:
  - lazarus-group
  - macos
  - malware
  - fileless
  - applejeus
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://objective-see.org/blog/blog_0x54.html
iocs:
  - type: md5
    value: 6588d262529dc372c400bef8478c2eec
ioc_counts:
  md5: 1
rules:
  - title: Detect Base64 Encoded Data in Process Memory
    description: Detects base64 encoded data being processed or loaded into memory by a specific process, which could indicate the presence of a fileless payload.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_memory
      - macos
  - title: Detect MD5 Hash of System Serial Number
    description: Detects the execution of md5 hash generation with the system serial number as input.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

The Lazarus Group's macloader malware, internally named 'macloader' and externally identified as OSX.AppleJeus.C, exhibits advanced techniques for macOS malware. Discovered in late 2019, this malware employs a launch daemon for persistence at `/Library/LaunchDaemons/vip.unioncrypto.plist` pointing to `/Library/UnionCrypto/unioncryptoupdater`. A key feature is its ability to execute second-stage payloads directly from memory, enhancing stealth and complicating forensic analysis. The malware communicates with its command and control (C&C) server at `https://unioncrypto.vip/update` to retrieve these payloads. This "fileless" execution capability makes it a potent threat, as the payloads never touch the file system. The malware beacons out providing basic system information (macOS version, serial number) and the implant version ("1.0"). This malware is notable for its in-memory execution of downloaded payloads.

## Attack Chain

1.  The malware is initially deployed on the system (delivery mechanism unspecified in the source).
2.  Persistence is established via a launch daemon at `/Library/LaunchDaemons/vip.unioncrypto.plist` pointing to `/Library/UnionCrypto/unioncryptoupdater`.
3.  The malware beacons out to the C&C server `https://unioncrypto.vip/update` to check for updates. It sends system information, including macOS version and serial number, in the POST request.
4.  The C&C server responds with an HTTP 200 OK, containing at least 0x400 bytes of base64-encoded data representing the second-stage payload.
5.  The malware base64-decodes the received data.
6.  The malware calculates an MD5 hash of the system's serial number (prefixed with 0x18).
7.  The malware decrypts part of the decoded payload using AES-CBC with a key and IV.
8.  The malware loads and executes the decrypted second-stage payload directly from memory using the `load_from_memory` function. The final objective is to execute arbitrary code without writing to disk.

## Impact

Successful execution of this malware allows attackers to gain a persistent foothold on macOS systems, execute arbitrary code, and potentially exfiltrate sensitive data. The fileless nature of the second-stage payload makes detection and forensic analysis significantly more challenging. The malware's capabilities could be repurposed by other threat actors for various malicious activities, including espionage, data theft, or deployment of additional malware. The number of victims and specific sectors targeted are not specified in the source.

## Recommendation

*   Monitor for the creation of launch daemons with the name `vip.unioncrypto.plist` and pointing to `/Library/UnionCrypto/unioncryptoupdater` using a file integrity monitoring tool (related to Attack Chain step 2).
*   Implement a network detection rule to identify connections to the C&C server `unioncrypto.vip` (IOC - domain).
*   Deploy the Sigma rule "Detect Base64 Encoded Data in Process Memory" to identify potential in-memory payloads (related to Attack Chain step 5).
*   Monitor process creation events for `unioncryptoupdater` to identify potential execution of the first-stage loader.
*   Implement the Sigma rule "Detect MD5 Hash of System Serial Number" to identify potential MD5 hashing of the Mac OS serial number.
