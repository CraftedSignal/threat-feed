---
title: Maltrail IOC Feed Update for Multiple Threats
slug: 2026-03-maltrail-iocs
description: This brief summarizes IOCs extracted from the Maltrail feed on March 15, 2026, covering domains and URLs associated with threats targeting macOS and Android platforms, including OSX_Atomic, FakeApp, Android_Joker, Lummack2, APT_Sidewinder, APT_Kimsuky, and Hak5Cloud_C2.
date: "2026-03-15T21:00:08Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - maltrail
  - ioc
  - osx
  - android
  - apt
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal on Host
references:
  - https://www.circl.lu/doc/misp/feed-osint/878f5b33-0fcf-4191-8295-4bcddeb6437a.json
  - https://api.github.com/repos/stamparm/maltrail/commits/a3681b0b82849e400e3b2ffd5b30608abf1bb7f1
  - https://api.github.com/repos/stamparm/maltrail/commits/b681d4bce01b9723fab2ce0ea10133353f943434
  - https://api.github.com/repos/stamparm/maltrail/commits/2065e8ab6f15b8cdeeb24a07fab8d849fc9e6935
  - https://api.github.com/repos/stamparm/maltrail/commits/75f0bd1595532bf7fafcf9cfcc1caf4b1e6b4267
  - https://api.github.com/repos/stamparm/maltrail/commits/fcf8b4ecf7b8aed41bb22bfe41fe52ea3c076f40
  - https://api.github.com/repos/stamparm/maltrail/commits/ce05d11717590e58ed4f2ff73759262c90789426
  - https://api.github.com/repos/stamparm/maltrail/commits/83fd2c39f154b193baaf1753656a598bbbf276b9
  - https://api.github.com/repos/stamparm/maltrail/commits/23476cd55bd5a2e74485e8bd710c9b9b4cdfcfc5
  - https://api.github.com/repos/stamparm/maltrail/commits/fd7a3895e500e82b02c6b97f9de338c598120ad8
  - https://api.github.com/repos/stamparm/maltrail/commits/8273ebec7b56bffd4c5c44eb7b22e7f5021fdd39
iocs:
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/a3681b0b82849e400e3b2ffd5b30608abf1bb7f1
  - type: domain
    value: appsformacs.com
  - type: domain
    value: ariaplus.me
  - type: domain
    value: biscuit.legionkraken.io
  - type: domain
    value: coinmarketloans.com
  - type: domain
    value: creptomus.com
  - type: domain
    value: criptomus.com
  - type: domain
    value: cryptomuc.com
  - type: domain
    value: cryptomus-app.com
  - type: domain
    value: cryptomus-payment-check.com
  - type: domain
    value: cryptomus-payments.com
  - type: domain
    value: cryptomus-wallet.com
  - type: domain
    value: cryptomus.live
  - type: domain
    value: cryptomustestnetik.icu
  - type: domain
    value: gq.legionkraken.io
  - type: domain
    value: holder.money
  - type: domain
    value: info.ariaplus.me
  - type: domain
    value: invoice-crypomus.com
  - type: domain
    value: invoice-crypotmus.com
  - type: domain
    value: octotore.com
  - type: domain
    value: pay.cryptomus.live
  - type: domain
    value: site.ariaplus.me
  - type: domain
    value: torrents4mac.com
  - type: domain
    value: vrsmm.com
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/b681d4bce01b9723fab2ce0ea10133353f943434
  - type: domain
    value: adhushapp-razvd.com
  - type: domain
    value: aiassistant.sbs
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/2065e8ab6f15b8cdeeb24a07fab8d849fc9e6935
  - type: domain
    value: snapplix-cttt.tech
  - type: domain
    value: stealthwall-cttf.tech
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/75f0bd1595532bf7fafcf9cfcc1caf4b1e6b4267
  - type: domain
    value: frude.biz
  - type: domain
    value: semer.bond
  - type: domain
    value: zagat.cyou
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/fcf8b4ecf7b8aed41bb22bfe41fe52ea3c076f40
  - type: domain
    value: police-center.vg
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/ce05d11717590e58ed4f2ff73759262c90789426
  - type: domain
    value: chromium-report-tech-331as-2s1-tcd-h143.redticker-ctfff.tech
  - type: domain
    value: chromium-report-tech-331as-2s1-tcd-h143.webplix-cctf.tech
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/83fd2c39f154b193baaf1753656a598bbbf276b9
  - type: domain
    value: onev.online
  - type: domain
    value: visa.nadra.gov-pk.info
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/23476cd55bd5a2e74485e8bd710c9b9b4cdfcfc5
  - type: domain
    value: naver.liferod.com
  - type: domain
    value: nid.naver.liferod.com
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/fd7a3895e500e82b02c6b97f9de338c598120ad8
  - type: domain
    value: c2.socops.net
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/8273ebec7b56bffd4c5c44eb7b22e7f5021fdd39
  - type: domain
    value: join86s.dynv6.net
  - type: domain
    value: nid-naverxil.onthewifi.com
ioc_counts:
  domain: 40
  url: 10
rules:
  - title: Detect Network Connection to Hak5Cloud C2 Domain
    description: Detects network connections to the Hak5Cloud command and control domain.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Connection to APT_Sidewinder Domain
    description: Detects network connections to a domain associated with APT_Sidewinder.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Connection to FakeApp Domains
    description: Detects network connections to domains associated with FakeApp malware.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This threat brief highlights indicators of compromise (IOCs) identified on March 15, 2026, through the Maltrail feed. The identified IOCs are associated with a variety of threat actors and malware families, targeting both macOS and Android operating systems. The threats include OSX_Atomic, which potentially delivers malware to macOS systems; FakeApp, used for deceptive applications; Android_Joker, a known Android malware family; Lummack2, an information stealer; APT_Sidewinder, an advanced persistent threat actor; APT_Kimsuky, another APT group; and Hak5Cloud_C2, related to Hak5 Cloud Command and Control infrastructure. This diverse set of IOCs underscores the wide range of threats organizations face and the importance of monitoring network traffic and system logs for malicious activity. This data is crucial for detection engineers to build and deploy relevant detection rules to protect their environments.

## Attack Chain

1.  **Initial Access (OSX_Atomic/FakeApp):** User downloads a seemingly legitimate application from a compromised website (e.g., `appsformacs.com`, `torrents4mac.com`, or a FakeApp site like `adhushapp-razvd.com`).
2.  **Execution (OSX_Atomic/FakeApp):** The downloaded application is executed on the user's macOS or Android device. This may involve bypassing security warnings or exploiting vulnerabilities.
3.  **Persistence (OSX_Atomic/Android_Joker):** The malware establishes persistence on the system, potentially using techniques such as modifying startup items or scheduled tasks (OSX_Atomic), or registering as a background service (Android_Joker).
4.  **Command and Control (Multiple):** The malware connects to a command-and-control (C2) server (e.g., `c2.socops.net`, `onev.online`) to receive instructions and exfiltrate data.
5.  **Credential Theft (Lummack2):** The malware attempts to steal credentials stored on the system or in web browsers, potentially using keylogging or form grabbing techniques (Lummack2).  Observed communicating with `police-center.vg`.
6.  **Data Exfiltration (Multiple):** Sensitive data, such as credentials, financial information, or personal data, is exfiltrated to the C2 server.
7.  **Lateral Movement (APT_Sidewinder/APT_Kimsuky):** The attacker uses the compromised system to move laterally within the network, targeting other systems and data.  APT_Sidewinder uses domains like `visa.nadra.gov-pk.info` while APT_Kimsuky leverages `naver.liferod.com` for potential C2 or phishing activities.
8.  **Impact (Multiple):** The attacker achieves their objectives, which may include financial gain (through fraud or extortion), intellectual property theft, or espionage.

## Impact

The identified IOCs represent a diverse range of threats that can have significant impact on organizations and individuals. Successful attacks can lead to financial losses due to fraud or ransomware, data breaches resulting in the theft of sensitive information, and reputational damage. The targeting of macOS and Android devices indicates a broad scope of potential victims, encompassing both corporate and personal devices. The involvement of APT groups like APT_Sidewinder and APT_Kimsuky suggests potential for targeted attacks with significant impact on national security or critical infrastructure. A single successful infection can lead to widespread compromise within an organization's network.

## Recommendation

*   Block the malicious domains listed in the IOC table at the DNS resolver and firewall to prevent communication with known C2 infrastructure.
*   Implement a network intrusion detection system (NIDS) rule to detect connections to the malicious domains and URLs (IOCs) to identify potentially compromised systems.
*   Deploy the Sigma rules provided below to your SIEM and tune them for your specific environment to detect suspicious process execution and network connections.
*   Investigate systems communicating with any of the listed IOCs (domains/URLs) for signs of malware infection or unauthorized access.
