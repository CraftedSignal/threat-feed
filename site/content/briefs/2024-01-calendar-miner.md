---
title: Calendar 2 Mac App Store Application Mines Cryptocurrency
slug: 2024-01-calendar-miner
description: The 'Calendar 2' application, available on the official Mac App Store, was found to surreptitiously mine cryptocurrency on users' Macs, utilizing the 'xmr-stak' miner to mine Monero (XMR) and report mining operations to calendar.qbix.com.
date: "2024-01-03T18:21:00Z"
type: threat
types:
  - threat
severities:
  - medium
tags:
  - cryptocurrency
  - miner
  - macos
  - appstore
vendors:
  - Apple
  - Qbix
products:
  - Calendar 2
  - Coinstash app
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1496
    technique_name: Resource Hijacking
references:
  - https://objective-see.org/blog/blog_0x2B.html
rules:
  - title: Detect xmr-stak Miner Execution
    description: Detects the execution of the xmr-stak miner, often used for mining Monero.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1496
    data_sources:
      - process_creation
      - macos
  - title: Detect Mining Statistics Upload to Calendar.qbix.com
    description: Detects network connections posting mining statistics to the Calendar.qbix.com domain.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - macos
  - title: File Integrity Monitoring of Application Frameworks
    description: Detects modification to an application's framework directory, potentially indicating malicious activity
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - macos
rules_count: 3
---

In March 2018, the "Calendar 2" application, distributed via the official Mac App Store, was discovered to contain hidden cryptocurrency mining capabilities. The application, developed by Qbix, utilized the 'xmr-stak' miner to mine Monero (XMR) in the background, without clearly notifying users of this activity. The mining operation's statistics were reported to a remote server. While the application did contain some level of disclosure regarding its mining activities, users expressed dissatisfaction. The application has since been removed from the Mac App Store following reports to Apple. The discovery highlights the challenges of vetting applications in official app stores and the potential for abuse of system resources for financial gain.

## Attack Chain

1. A user downloads and installs the "Calendar 2" application from the official Mac App Store.
2. Upon launch, the application's `applicationDidFinishLaunching:` delegate method executes.
3. This triggers a call to `[MinerManager manager]` which initializes a `MinerManager` object.
4. During initialization, the `runMining` method is invoked.
5. The `runMining` method interacts with the `Coinstash_XMRSTAK.framework`, specifically calling the `+[Coinstash_XMRSTAK.Coinstash startMiningWithPort:password:coreCount:slowMemory:currency:]` method.
6. This method executes the `xmr-stak` miner binary located within the framework.
7. The `xmr-stak` miner connects to a mining pool (`pool.graft.hashvault.pro:7777`) and begins mining Monero (XMR) using CPU resources.
8. The application periodically sends mining statistics to `calendar.qbix.com/api/mining`.

## Impact

The "Calendar 2" application surreptitiously utilized users' CPU resources to mine Monero, leading to performance degradation and increased power consumption. While the exact number of affected users is unknown, the application's presence on the Mac App Store suggests a potentially wide reach. Successful exploitation could lead to reduced system lifespan due to increased heat and stress on hardware components. The mining profits accrued by the developer, greg@qbix.com, at the expense of unsuspecting users.

## Recommendation

*   Monitor process creations for the execution of `xmr-stak` from within application frameworks, using the provided Sigma rule, to detect potentially malicious cryptocurrency mining activity.
*   Enable process monitoring with command-line argument logging to identify processes connecting to known cryptocurrency mining pools (see `xmr-stak` command-line arguments in the attack chain).
*   Inspect network traffic for connections to `calendar.qbix.com/api/mining` to identify applications reporting mining statistics.
*   Deploy the file integrity monitoring rule to track changes in application frameworks that may indicate the addition of mining capabilities.
