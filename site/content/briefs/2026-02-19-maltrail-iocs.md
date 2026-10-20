---
brief_id: brief-2026-02-19-maltrail-iocs
event_id: brief-2026-02-19-maltrail-iocs
revision: 2
activity_at: "2026-02-19T16:36:58Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:79e005473561fbcec6c83cfe1678c48b228bc9be1942f9f1945cbd83bac3d41f
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Maltrail Feed IOCs Targeting Multiple Verticals
slug: 2026-02-19-maltrail-iocs
description: This brief covers newly identified malicious domains and IPs from the Maltrail feed on 2026-02-19, which are actively being used in various campaigns to deliver malware and facilitate command and control.
date: "2026-02-19T16:36:58Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
tags:
  - maltrail
  - ioc
  - domain
  - ip
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://www.circl.lu/doc/misp/feed-osint/4fe4a80e-39cb-43f1-9e95-9ce5ddd98907.json
  - https://api.github.com/repos/stamparm/maltrail/commits/11b8e64ee8f1179d3a57ed9d6acb04b6db98685f
  - https://api.github.com/repos/stamparm/maltrail/commits/1abcb0daf207436d840b79aa6a03dae8685b06dc
  - https://api.github.com/repos/stamparm/maltrail/commits/32a76ddc120c0277d847fbcbc9288d61621c6ada
  - https://api.github.com/repos/stamparm/maltrail/commits/891b85778a0dca163aab9a0357d4ad0070f1dde7
  - https://www.virustotal.com/gui/ip-address/172.86.68.175/relations
  - https://api.github.com/repos/stamparm/maltrail/commits/38a0e5323dfab3c52d49e9a5ebc378a77613c2e4
  - https://www.malware-traffic-analysis.net/2026/02/02/index.html
  - https://api.github.com/repos/stamparm/maltrail/commits/161165f924c2d4f0f724c560e8a61be490c2a32f
iocs:
  - type: domain
    value: koover.org
  - type: domain
    value: tributj.cyou
  - type: domain
    value: activebrain.conscious86jag.coupons
  - type: domain
    value: allu7eho1a.ru
  - type: domain
    value: censure47contr.coupons
  - type: domain
    value: checknode.censure47contr.coupons
  - type: domain
    value: conscious86jag.coupons
  - type: domain
    value: magicbook.overdue13wizard.coupons
  - type: domain
    value: magiclook.allu7eho1a.ru
  - type: domain
    value: mentalpulse.conscious86jag.coupons
  - type: domain
    value: mindwave.conscious86jag.coupons
  - type: domain
    value: mysticpoint.overdue13wizard.coupons
  - type: domain
    value: oldscroll.overdue13wizard.coupons
  - type: domain
    value: overdue13wizard.coupons
  - type: domain
    value: safeguard.censure47contr.coupons
  - type: domain
    value: schonefrau.allu7eho1a.ru
  - type: domain
    value: shieldpath.censure47contr.coupons
  - type: domain
    value: thoughtsync.conscious86jag.coupons
  - type: domain
    value: topazyduper.ru
  - type: domain
    value: nelavohomet.com
  - type: domain
    value: abjmamnaaecgfmd.top
  - type: domain
    value: addmkkajhebcbem.top
  - type: domain
    value: afiniljgdmdgimb.top
  - type: domain
    value: agcnfjkcjlcddfk.top
  - type: domain
    value: ahegbcanlikmall.top
  - type: domain
    value: ahyw2fb2.top
  - type: domain
    value: aimgmacjdijjjeg.top
  - type: domain
    value: aldhkakgnbkmdmk.top
  - type: domain
    value: baifegjcmijlifc.top
  - type: domain
    value: basy3f.top
  - type: domain
    value: bfbkidlkalaelfj.top
  - type: domain
    value: bhflgeggjeciean.top
  - type: domain
    value: binlcchccebfagh.top
  - type: domain
    value: bkbemjmaebjnkmi.top
  - type: domain
    value: bljejhnjkaikgfd.top
  - type: domain
    value: bnafhhhggikannh.top
  - type: domain
    value: bnbfyw1.top
  - type: domain
    value: ccldeaegnbjckae.top
  - type: domain
    value: cdfdbmgcfainfgn.top
  - type: domain
    value: cegklfkahlchcna.top
  - type: ip
    value: 144.31.238.37
  - type: ip
    value: 85.137.253.64
ioc_counts:
  domain: 40
  ip: 2
rules:
  - title: Detect Connection to Malicious Domain from Maltrail Feed
    description: Detects network connections to domains identified as malicious in the Maltrail feed.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Connection to Malicious IP from Maltrail Feed
    description: Detects network connections to IPs identified as malicious in the Maltrail feed.
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

On 2026-02-19, the Maltrail feed identified a series of new malicious domains and IP addresses involved in suspicious network activity. This activity is likely related to ongoing campaigns aimed at delivering malware, conducting phishing attacks, or establishing command and control infrastructure. The identified domains use various techniques, including the generation of seemingly random character strings and the exploitation of coupon-related themes. The diverse naming schemes suggests a broad targeting scope rather than a single, focused campaign. Defenders should monitor and block these indicators to prevent potential compromise of their systems. Due to the nature of the Maltrail feed, specific attribution and campaign details are not available; however, proactive blocking of these indicators is crucial.

## Attack Chain

1. **Initial Access:** Users unknowingly visit or are redirected to malicious domains (e.g., koover.org, tributj.cyou, activebrain.conscious86jag.coupons).
2. **Redirection:** The initial domain may redirect the user to other malicious sites or serve malicious content directly.
3. **Exploitation (Possible):** If the user's system has unpatched vulnerabilities, the attacker may attempt to exploit them through drive-by download techniques.
4. **Malware Delivery:** A malicious payload (e.g., trojan, infostealer) is delivered to the victim's system.
5. **Installation:** The malware installs itself on the system, often using persistence mechanisms to ensure it runs after reboot.
6. **Command and Control:** The malware establishes communication with a command and control (C2) server using IP addresses such as 144.31.238.37 and 85.137.253.64.
7. **Data Exfiltration/Malicious Activity:** The attacker uses the compromised system to exfiltrate sensitive data or perform other malicious activities, such as lateral movement within the network.

## Impact

A successful attack using these indicators could lead to data breaches, financial losses, and reputational damage. The wide range of domains suggests a broad targeting scope, potentially impacting numerous organizations and individuals. Compromised systems could be used to launch further attacks, spreading the malware to other victims. Given the lack of specific victimology in the source data, the potential impact is difficult to quantify, but defenders should treat these indicators as high priority.
