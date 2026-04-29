---
title: Maltrail IOCs for Android Joker, APT Lazarus, UNC2465, and Powershell Injector
slug: 2026-02-maltrail-iocs
description: This brief covers IOCs associated with Android Joker malware, APT Lazarus group, APT UNC2465 activity, and PowerShell Injector campaigns identified by Maltrail on February 25, 2026.
date: "2026-02-25T22:01:17Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - maltrail
  - ioc
  - android_joker
  - apt_lazarus
  - unc2465
  - powershell_injector
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://www.circl.lu/doc/misp/feed-osint/6af94a64-39c8-4066-a702-7ad7b9cc5cdd.json
iocs:
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/96912006c1e73a8654d881938df2fbc3285525cf
  - type: domain
    value: genad.click
  - type: domain
    value: infkm.bond
  - type: domain
    value: stmuis.help
  - type: domain
    value: suluk.cyou
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/86d172cc9700912c7505a1f8e2212a8f0a36846f
  - type: ip
    value: 147.124.214.235
  - type: domain
    value: app.breezyhr.us
  - type: domain
    value: breezyhr.us
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/ca426025791afbb1adbd61cf1bc0542e7e0b703c
  - type: domain
    value: hornetseculty.com
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/ff57848255e0c2f3649dc297b210c0730fc5105b
  - type: url
    value: https://x.com/malwrhunterteam/status/2026412293878157472
  - type: url
    value: https://www.virustotal.com/gui/file/7cdc63f6cb960db552cdc88e96315b0dc6a7f1418afa452ae325c197351fa8de/detection
  - type: domain
    value: cdn0x.store
  - type: domain
    value: 101centricconsulting.click
  - type: domain
    value: 101macroconsulting.click
  - type: domain
    value: 101pulsestrategy.click
  - type: domain
    value: 1forgelumen.click
  - type: domain
    value: 1quantumhub.click
  - type: domain
    value: 1technoplus.click
  - type: domain
    value: 2024.monadnetwork.app
  - type: domain
    value: 2025ultraworks.click
  - type: domain
    value: 247novaflow.sbs
  - type: domain
    value: 2alphadomain.click
  - type: domain
    value: 2insightglobal.click
  - type: domain
    value: 2stratamax.sbs
  - type: domain
    value: 360alphaadvisory.sbs
  - type: domain
    value: 360centricfusion.digital
  - type: domain
    value: advanta8resources.click
  - type: domain
    value: aeroedgeinsight.click
  - type: domain
    value: aerogrouply.click
  - type: domain
    value: aerostrategyinnovate.click
  - type: domain
    value: alphahorizonventures.sbs
  - type: domain
    value: analytic.monadnetwork.app
  - type: domain
    value: analytics360ev-olve.sbs
  - type: domain
    value: antiguacasadelplomero.com.mx
  - type: domain
    value: apex247forge.buzz
  - type: domain
    value: apex247po-int.forum
  - type: domain
    value: apex365prime.sbs
  - type: domain
    value: apexonebase.pics
  - type: domain
    value: astroflowventures.click
  - type: domain
    value: astronextconsulting.click
  - type: domain
    value: astroprimeinnovate.click
  - type: domain
    value: axion48industries.click
  - type: domain
    value: axis247media.click
  - type: domain
    value: badasusoziusadvisoryco.pics
  - type: domain
    value: badufuciuminvestments.digital
  - type: domain
    value: bakoyuvaaservices.sbs
ioc_counts:
  domain: 42
  ip: 1
  url: 6
rules:
  - title: Detect PowerShell Encoded Commands
    description: Detects PowerShell commands using the -enc or -EncodedCommand parameters, which are often used to obfuscate malicious scripts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Outbound Connections to APT Lazarus IP
    description: Detects network connections to the IP address associated with APT Lazarus activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Connection to Newly Observed Domains
    description: Detects network connections to domains observed in the Maltrail feed, which could indicate new or emerging threats.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1568.002
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This threat brief summarizes indicators of compromise (IOCs) identified by Maltrail on February 25, 2026, linking to several distinct threat actors and campaigns. These include the Android Joker malware known for its malicious billing fraud, APT Lazarus group, APT UNC2465, and campaigns involving the use of PowerShell injectors. The IOCs consist of domains and URLs related to network activity and external analysis of these threats. Notably, a large number of domains were identified without specific attribution, potentially representing a broader infrastructure used across multiple campaigns. Defenders should utilize these IOCs to proactively identify and block malicious activity targeting their networks.

## Attack Chain

The following attack chain represents a generalized view based on the observed indicators, as the specific methods vary between the threat actors:

1.  **Initial Compromise:** (Observed for Android Joker): User unknowingly installs a malicious application containing the Joker malware from a third-party app store or via sideloading.
2.  **Persistence (Android Joker):** The malware establishes persistence on the device, often by hiding itself or masquerading as a legitimate application.
3.  **Command and Control (Various):** The compromised system communicates with command-and-control (C2) servers using domains like `genad.click`, `infkm.bond`, `stmuis.help`, `suluk.cyou`, or others listed in the IOCs.
4.  **PowerShell Injection (PowerShell Injector):** A PowerShell script is executed to inject malicious code into another process, often to evade detection. This may involve domains like `cdn0x.store`.
5.  **Credential Harvesting (APT Lazarus):** The Lazarus Group attempts to steal credentials and other sensitive information from the compromised system to facilitate lateral movement.
6.  **Lateral Movement (APT Lazarus, UNC2465):** Using stolen credentials or exploiting vulnerabilities, the attacker moves laterally to other systems within the network, potentially leveraging infrastructure related to `hornetseculty.com`, `app.breezyhr.us`, and `breezyhr.us`.
7.  **Data Exfiltration (APT Lazarus, UNC2465):** Sensitive data is exfiltrated from the compromised network to attacker-controlled infrastructure.
8.  **Monetary Gain/Espionage (Android Joker, APT Lazarus, UNC2465, PowerShell Injector):** The ultimate objective ranges from financial gain (Android Joker, PowerShell Injector) through fraudulent activities or data theft to espionage or disruption (APT Lazarus, UNC2465) targeting specific organizations or sectors.

## Impact

Successful exploitation can lead to significant financial losses for victims of Android Joker through billing fraud. APT Lazarus and UNC2465 intrusions can result in the theft of sensitive data, intellectual property, and disruption of critical services. The large number of unattributed domains suggests a broad and potentially widespread malicious infrastructure, which could be leveraged in various campaigns impacting multiple sectors.

## Recommendation

*   Monitor network traffic for connections to the domains listed in the IOC table and block them at the firewall or DNS resolver to disrupt communication with attacker infrastructure.
*   Implement the Sigma rule for PowerShell injection to detect suspicious PowerShell activity and potential code injection attempts.
*   Review network connection logs for connections to the IP address `147.124.214.235`, associated with APT Lazarus.
*   Investigate systems that have communicated with any of the unattributed domains in the IOCs to identify potential compromise.
