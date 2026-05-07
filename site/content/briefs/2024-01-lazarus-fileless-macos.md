---
title: Lazarus Group's macOS 'Fileless' Implant
slug: 2024-01-lazarus-fileless-macos
description: The Lazarus APT group is distributing a trojanized macOS application named UnionCryptoTrader.dmg that installs a launch daemon for persistence, downloads and executes secondary payloads in-memory, and communicates with the command and control server unioncrypto.vip.
date: "2024-01-02T12:00:00Z"
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
  - lazarus
  - fileless
  - macos
  - trojan
vendors:
  - Apple
products:
  - macos
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://objective-see.org/blog/blog_0x51.html
iocs:
  - type: md5
    value: 6588d262529dc372c400bef8478c2eec
  - type: ip
    value: 104.168.167.16
  - type: url
    value: https://www.unioncrypto.vip/download/W6c2dq8By7luMhCmya2v97YeN
ioc_counts:
  ip: 1
  md5: 1
  url: 1
rules:
  - title: Detect UnionCryptoTrader Package Installation
    description: Detects the execution of the UnionCryptoTrader.pkg installer.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - process_creation
      - macos
  - title: Detect UnionCryptoUpdater Execution
    description: Detects the execution of the unioncryptoupdater binary from /Library/UnionCrypto.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - macos
  - title: Detect Network Connection to UnionCrypto VIP Domain
    description: Detects network connections to the UnionCrypto VIP domain.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - macos
rules_count: 3
---

The Lazarus Group, known for targeting cryptocurrency exchanges, continues to evolve its macOS capabilities. This campaign, observed in late 2019, involves a trojanized application named UnionCryptoTrader.dmg, masquerading as a legitimate cryptocurrency trading platform. The application, hosted on the domain unioncrypto.vip (104.168.167.16), is delivered to victims via an assumed download link. Once executed, the application installs a persistent launch daemon and then downloads and executes further payloads directly in memory, minimizing its footprint on the compromised system. This 'fileless' approach, combined with targeting of cryptocurrency platforms, demonstrates Lazarus Group's ongoing interest in financial gain and their increasing sophistication in macOS malware development.

## Attack Chain

1.  The victim downloads a disk image (UnionCryptoTrader.dmg) from unioncrypto.vip.
2.  The victim mounts the DMG, revealing an unsigned package installer (UnionCryptoTrader.pkg).
3.  The victim executes the package, which prompts for administrator credentials due to the installation of a launch daemon.
4.  The postinstall script within the package moves a hidden plist file (.vip.unioncrypto.plist) to `/Library/LaunchDaemons/vip.unioncrypto.plist` for persistence.
5.  The script also moves a hidden executable (.unioncryptoupdater) to `/Library/UnionCrypto/unioncryptoupdater` and sets its permissions to executable.
6.  The launch daemon (`/Library/UnionCrypto/unioncryptoupdater`) is executed and configured to run on each system reboot.
7.  The `unioncryptoupdater` binary gathers system information, including the serial number using IOKit (`IOPlatformSerialNumber`).
8.  The `unioncryptoupdater` binary connects to the C2 server `unioncrypto.vip/update` to download and execute payloads in memory.

## Impact

This attack targets employees of cryptocurrency exchanges. Successful infection allows the Lazarus Group to gain persistent access to systems within these organizations, potentially leading to theft of cryptocurrency, sensitive financial data, or disruption of trading operations. The fileless nature of the secondary payload execution makes detection more difficult, increasing the attacker's dwell time and potential for damage.

## Recommendation

*   Monitor for the creation of launch daemons by unsigned installers, specifically those moving plist files to `/Library/LaunchDaemons` (see attack chain steps 4-5).
*   Monitor network connections to `unioncrypto.vip` from unusual processes or those located in `/Library/UnionCrypto` using the provided IOCs.
*   Deploy the Sigma rule "Detect UnionCryptoTrader Package Installation" to identify the execution of the malicious installer.
*   Block the domain `unioncrypto.vip` at the network perimeter (DNS or firewall) to prevent initial infection and C2 communication using the provided IOC.
*   Enable endpoint detection and response (EDR) systems to detect and block the execution of unsigned binaries from `/Library/UnionCrypto`.
