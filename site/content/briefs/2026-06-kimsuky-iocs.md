---
title: Kimsuky APT Domains and URLs from Maltrail Feed
slug: 2026-06-kimsuky-iocs
description: This brief summarizes newly published IOCs consisting of domains and URLs associated with the Kimsuky APT group as of June 2nd, 2026, sourced from a Maltrail feed.
date: "2026-06-02T16:35:31Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - Kimsuky
  - Black Banshee
  - Velvet Chollima
  - Emerald Sleet
  - Thallium
tags:
  - kimsuky
  - apt
  - ioc
  - malware
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.circl.lu/doc/misp/feed-osint/87f831ba-5e47-4210-b79a-d733f70f4a00.json
iocs:
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/f04e78fc9e109400f740b2e34c86ad5630c7048a
  - type: domain
    value: 0jr87375qt.v6.navy
  - type: domain
    value: 2ecy51395u.v6.navy
  - type: domain
    value: b8fq9189g6.dns.navy
  - type: domain
    value: confirm1.moois-nid.remotewire.net
  - type: domain
    value: cxmfcubfnq.dns.navy
  - type: domain
    value: diaxwn61lp.dynv6.net
  - type: domain
    value: dns-setup.remotewire.net
  - type: domain
    value: e639kk.wjyx49u3cu3.dns.army
  - type: domain
    value: egbzqa25gw.v6.navy
  - type: domain
    value: health-doc.giize.com
  - type: domain
    value: info.dns-setup.remotewire.net
  - type: domain
    value: ip-cloud.theworkpc.com
  - type: domain
    value: ips-doc.webredirect.org
  - type: domain
    value: ips.dynuddns.net
  - type: domain
    value: ispd.nts-write.remotewire.net
  - type: domain
    value: jbyaa6xotk.v6.army
  - type: domain
    value: lopm.webredirect.org
  - type: domain
    value: mois-doc.roxa.org
  - type: domain
    value: mois.mytunnel.org
  - type: domain
    value: moois-nid.remotewire.net
  - type: domain
    value: ms-cloud.ezgateway.net
  - type: domain
    value: mybox.camdvr.org
  - type: domain
    value: n-corp.hets12ex.dns.army
  - type: domain
    value: n2gdnw08p4.dns.navy
  - type: domain
    value: nav-log.moois-nid.remotewire.net
  - type: domain
    value: naver.mywire.org
  - type: domain
    value: ncodcnpass.dns.navy
  - type: domain
    value: nd8f3lxih4.v6.navy
  - type: domain
    value: ndoc.nid-sign.opik.net
  - type: domain
    value: nid-nver.mybox.camdvr.org
  - type: domain
    value: nid-sign.opik.net
  - type: domain
    value: nid.ips-doc.webredirect.org
  - type: domain
    value: nid.naver.mywire.org
  - type: domain
    value: nid.ncodcnpass.dns.navy
  - type: domain
    value: nid.nid-sign.opik.net
  - type: domain
    value: nid.niws.mysynology.net
  - type: domain
    value: nid.puoios.o-r.kr
  - type: domain
    value: niws.mysynology.net
  - type: domain
    value: nj1oayuy2o.dns.army
  - type: domain
    value: nps-load.remotewire.net
  - type: domain
    value: nst.mysynology.net
  - type: domain
    value: nts-write.remotewire.net
  - type: domain
    value: nudoc-check.e639kk.wjyx49u3cu3.dns.army
  - type: domain
    value: nusrauth.gleeze.com
  - type: domain
    value: passnid.lopm.webredirect.org
  - type: domain
    value: puoios.o-r.kr
  - type: domain
    value: r461wn14u1.dns.army
  - type: domain
    value: support.nst.mysynology.net
  - type: domain
    value: tahpuoto94.dns.army
ioc_counts:
  domain: 49
  url: 1
rules:
  - title: Detect DNS Queries to Kimsuky Domains
    description: Detects DNS queries to domains associated with the Kimsuky APT group.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.004
    data_sources:
      - dns_query
      - windows
  - title: Detect Outbound Connection to Kimsuky Domains
    description: Detects outbound network connections to domains associated with the Kimsuky APT group.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

This threat brief summarizes indicators of compromise (IOCs) associated with the Kimsuky APT group, a North Korean threat actor known for cyber espionage and intelligence gathering. The IOCs, consisting of domains and a URL, were extracted from a Maltrail feed published on June 2nd, 2026. These indicators can be used to identify and block malicious network traffic related to Kimsuky's activities. Kimsuky is known to target South Korean government entities, think tanks, and individuals involved in foreign policy and national security. The group employs a variety of techniques, including spear-phishing, watering hole attacks, and the use of custom malware. These IOCs are likely associated with command-and-control infrastructure or phishing campaigns.

## Attack Chain

While this report focuses primarily on IOCs, a typical Kimsuky attack chain might involve the following steps:

1.  **Spear-phishing:** Kimsuky initiates contact via highly targeted spear-phishing emails, often masquerading as legitimate correspondence from trusted sources.
2.  **Malicious Attachment/Link:** The emails contain malicious attachments (e.g., weaponized documents) or links that lead to compromised websites.
3.  **Initial Access:** Upon opening the attachment or clicking the link, malware is executed on the victim's machine.
4.  **Persistence:** The malware establishes persistence through various methods, such as scheduled tasks or registry modifications, to ensure continued access to the system.
5.  **Command and Control:** The malware connects to command-and-control (C2) servers to receive instructions and exfiltrate data. This is where the IOCs in this brief become relevant as potential C2 destinations.
6.  **Lateral Movement:** The attackers attempt to move laterally within the network, compromising additional systems and accounts.
7.  **Data Exfiltration:** Sensitive data is collected and exfiltrated to the attacker's servers.
8.  **Espionage:** The ultimate goal of Kimsuky is often espionage, gathering intelligence on South Korean government policies, defense strategies, and diplomatic relations.

## Impact

Compromise by Kimsuky can result in the loss of sensitive information, including government secrets, personal data, and intellectual property. This can have significant national security and economic consequences for targeted organizations. Successful attacks can also damage the reputation of affected entities and erode public trust. Given Kimsuky's focus on espionage, the primary impact is long-term strategic disadvantage for targeted nations.

## Recommendation

*   Ingest the domain IOCs listed in the `iocs` section into your SIEM or threat intelligence platform for alerting and blocking.
*   Monitor network traffic for connections to the domains and URL listed in the `iocs` section, specifically looking for suspicious outbound connections.
*   Deploy the Sigma rule provided below to detect DNS queries to Kimsuky infrastructure.
*   Investigate any systems that have communicated with the IOCs from this report, prioritizing systems belonging to users involved in South Korean foreign policy, national security, or defense.
