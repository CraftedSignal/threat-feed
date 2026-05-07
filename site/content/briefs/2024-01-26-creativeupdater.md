---
title: OSX/CreativeUpdater Cryptominer Distributed via MacUpdate
slug: 2024-01-26-creativeupdater
description: OSX/CreativeUpdater is a macOS cryptominer distributed through compromised download links on the MacUpdate website, using a trojanized application bundle to execute a script that downloads and installs a persistent Monero miner using launch agents.
date: "2024-01-26T18:22:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cryptominer
  - macos
  - malware
vendors:
  - Mozilla
  - Apple
products:
  - Firefox
  - OnyX
  - Deeper
  - Gatekeeper
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://objective-see.org/blog/blog_0x29.html
iocs:
  - type: url
    value: https://public.adobecc.com/files/1U14RSV3MVAHBMEGVS4LZ42AFNYEFF
  - type: url
    value: https://public.adobecc.com/files/1UJET2WD0VPD5SD0CRLX0EH2UIEEFF
  - type: ip
    value: 104.236.13.101
  - type: email
    value: sarahmayergo1990@gmail.com
  - type: email
    value: walker18@protonmail.ch
  - type: domain
    value: download-installer.cdn-mozilla.net
  - type: domain
    value: minergate.com
ioc_counts:
  domain: 2
  email: 2
  ip: 1
  url: 2
rules:
  - title: Detect Suspicious MacOSupdate.plist Launch Agent
    description: Detects the creation of a malicious launch agent file (MacOSupdate.plist) in the user's Library/LaunchAgents directory, indicative of OSX/CreativeUpdater infection.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - macos
  - title: Detect mdworker Process Execution from User Library
    description: Detects the execution of the 'mdworker' binary from the user's Library directory, a characteristic of OSX/CreativeUpdater's Monero miner.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - macos
  - title: Detect Outbound Network Connection to MinerGate
    description: Detects network connections to minergate.com
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - macos
rules_count: 3
---

OSX/CreativeUpdater is a macOS cryptominer that was distributed in early February 2018 via compromised download links on the popular MacUpdate website. The attack involved modifying download links for applications like Firefox, OnyX, and Deeper to point to a hacker-controlled URL (download-installer.cdn-mozilla.net) serving a trojanized version of the application. This trojanized application, disguised as a legitimate application and signed with an Apple Developer ID (Ramos Jaxson), bypasses Gatekeeper's default security settings. Once executed, the malware installs a persistent payload designed to mine Monero, impacting system performance and potentially allowing for future customized payloads. The use of MacUpdate as an infection vector allowed the malware to potentially infect a large number of macOS users.

## Attack Chain

1.  User visits MacUpdate and downloads a popular application (e.g., Firefox) from a compromised link.
2.  The user downloads a signed disk image (.dmg) containing a trojanized application bundle.
3.  The user mounts the disk image, bypassing Gatekeeper due to valid developer signature (Apple Developer ID: Ramos Jaxson).
4.  The user executes the trojanized application (e.g., Firefox.app), which in turn executes a script file located within the application's Resources directory.
5.  The script downloads a zip file (mdworker.zip) from a remote server (https://public.adobecc.com/files/1U14RSV3MVAHBMEGVS4LZ42AFNYEFF) and unzips it into the user's Library folder (~/Library/mdworker/).
6.  The script creates a LaunchAgent file (MacOSupdate.plist) in ~/Library/LaunchAgents/ to achieve persistence.
7.  The LaunchAgent loads, which in turn downloads another plist file (MacOS.plist) from a remote server (https://public.adobecc.com/files/1UJET2WD0VPD5SD0CRLX0EH2UIEEFF).
8.  The second plist file (MacOS.plist) executes the 'mdworker' binary, which is the MinerGate command-line cryptominer (minergate-cli), configured to mine Monero (XMR) using specific email addresses and, in some cases, a SOCKS proxy.

## Impact

Successful infection leads to the installation of a Monero cryptominer on the victim's macOS system. This results in high CPU usage and reduced system performance. The malware periodically connects to minergate.com, passing the email address as a login. The compromised applications included Firefox, OnyX and Deeper. Although the exact number of victims is unknown, the use of the popular MacUpdate platform as a distribution vector suggests a potentially wide impact.

## Recommendation

*   Deploy the Sigma rule "Detect Suspicious MacOSupdate.plist Launch Agent" to detect malicious launch agent files in the ~/Library/LaunchAgents/ directory.
*   Block the following domains at the DNS resolver to prevent the downloading of malicious payloads: public.adobecc.com and minergate.com (IOC table).
*   Monitor process execution for 'mdworker' running from the ~/Library/mdworker/ directory and alert if found (Sigma rule).
*   Inspect network connections for connections to the IP address 104.236.13.101 on port 1080, as this was used as a SOCKS proxy (IOC table).
