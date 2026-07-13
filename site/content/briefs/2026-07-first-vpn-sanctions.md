---
title: US Sanctions First VPN Service and Administrator for Aiding Ransomware Groups
slug: 2026-07-first-vpn-sanctions
description: The U.S. Treasury Department sanctioned First VPN Service (1VPNS) and its administrator, Dmytro Rashevskyi, for facilitating ransomware attacks by providing anonymity and evasion capabilities to cybercriminals, and also sanctioned Yegeniy Vladimirovich Silayev for selling 'cryptors' that make malware harder to detect, impacting critical infrastructure.
date: "2026-07-13T18:59:45Z"
lastmod: "2026-07-13T23:00:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sanctions
  - vpn
  - ransomware
  - cybercrime
  - defense-evasion
vendors:
  - First VPN Service
products:
  - First VPN Service
  - cryptors
  - 1VPNS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1090
    technique_name: Proxy
    evidence: First VPN Service (1VPNS) provided ransomware groups with tools to 'hide their identities... and evade detection'
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: Yegeniy Vladimirovich Silayev, was designated for allegedly selling 'cryptors,' or methods used to make malware harder to detect and more effective by cloaking it as harmless files.
    confidence_band: high
references:
  - https://therecord.media/first-vpn-administrator-us-sanctions-ransomware-groups
  - https://databreaches.net/2026/07/13/vpn-service-favored-by-ransomware-groups-is-sanctioned-by-us/?pk_campaign=feed&pk_kwd=vpn-service-favored-by-ransomware-groups-is-sanctioned-by-us
iocs:
  - type: company_name
    value: First VPN Service
  - type: alias
    value: 1VPNS
ioc_counts:
  alias: 1
  company_name: 1
updates:
  - at: "2026-07-13T23:00:12Z"
    level: L1
    summary: new IOCs
    sources:
      - databreaches
    source_urls:
      - https://databreaches.net/2026/07/13/vpn-service-favored-by-ransomware-groups-is-sanctioned-by-us/?pk_campaign=feed&pk_kwd=vpn-service-favored-by-ransomware-groups-is-sanctioned-by-us
---

The U.S. Treasury Department sanctioned First VPN Service (1VPNS) and its Ukrainian administrator, Dmytro Rashevskyi, on July 13, 2026, for providing crucial infrastructure that enabled ransomware groups to conduct attacks against American municipalities, hospitals, schools, and businesses. 1VPNS offered services designed to obscure attackers' identities, camouflage malicious software, and bypass detection, contributing to billions of dollars in losses for U.S. critical infrastructure. Rashevskyi reportedly used fake identities to secure server infrastructure, bypassing abuse complaints. Separately, Belarusian national Yegeniy Vladimirovich Silayev was also sanctioned for developing and selling "cryptors," tools that obfuscate malware to evade security defenses. This action follows a May takedown of First VPN by European law enforcement and the FBI, underscoring efforts to disrupt the cybercrime ecosystem by targeting enablers rather than just direct attackers. First VPN has operated since 2014, marketing itself on cybercrime forums for its anonymity features, including a no-logs policy and non-cooperation with law enforcement.

## Impact

The services provided by First VPN Service (1VPNS) and cryptor developer Yegeniy Vladimirovich Silayev significantly amplified the capabilities of ransomware groups, leading to substantial financial and operational damage. These enabling services contributed to ransomware attacks resulting in billions of dollars in losses for critical infrastructure providers across the U.S., including municipalities, hospitals, schools, and businesses. The sanctions aim to disrupt the financial and operational viability of such facilitators, thereby diminishing the overall effectiveness and reach of ransomware campaigns by making it harder for threat actors to hide their identities, evade detection, and secure necessary infrastructure. This action reduces the anonymity and resilience of cybercriminal operations.

## Recommendation

* Monitor `network_connection` logs for connections to unknown or suspicious VPN services that may be utilized by threat actors.
* Analyze `process_creation` and `file_event` logs for the execution of unusual or obfuscated binaries, indicative of malware utilizing cryptors to evade detection.
* Implement robust network segmentation and egress filtering to limit the impact of potential ransomware infections and prevent outbound connections to suspicious VPN endpoints.
* Deploy advanced endpoint detection and response (EDR) solutions with strong obfuscation detection capabilities to identify and block malware utilizing cryptors.
* Enforce strict application whitelisting policies to prevent the execution of unauthorized or crypted binaries.
