---
title: Maltrail IOCs for APT Kimsuky, Lummac2, MagentoCore, and FakeApp Campaigns
slug: 2026-05-maltrail-iocs
description: This brief summarizes indicators of compromise (IOCs) from a Maltrail feed update on 2026-05-20, detailing network activity associated with APT Kimsuky, Lummac2, MagentoCore, and FakeApp campaigns, providing actionable intelligence for detection and response.
date: "2026-05-20T22:12:32Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - APT Kimsuky
tags:
  - ioc
  - apt
  - network_activity
  - kimsuky
  - lummac2
  - magentocore
  - fakeapp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
references:
  - https://www.circl.lu/doc/misp/feed-osint/10c39115-7be2-45d1-884f-8125733c1b92.json
  - https://api.github.com/repos/stamparm/maltrail/commits/f9324a40cdba2fc8c6e71245aa98be2c0d17f04c
  - https://x.com/skocherhan/status/2057172575889789202
  - https://api.github.com/repos/stamparm/maltrail/commits/f20c6823363a1cd1b330b4b4a9891beec7f27aec
  - https://api.github.com/repos/stamparm/maltrail/commits/e202683c7f0d46980803d6b05a038f2b819a43b2
  - https://api.github.com/repos/stamparm/maltrail/commits/581025fa091e6a2594d7a849980caa94b438a982
  - https://x.com/Malwarehunterr/status/2057196561172689389
iocs:
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/f9324a40cdba2fc8c6e71245aa98be2c0d17f04c
  - type: url
    value: https://x.com/skocherhan/status/2057172575889789202
  - type: domain
    value: 2u9f.2usrmmwwduz.dns.navy
  - type: domain
    value: 2usrmmwwduz.dns.navy
  - type: domain
    value: 6td4w.mj9tqlj86sz.dns.navy
  - type: domain
    value: 923h5qvvzq2.v6.navy
  - type: domain
    value: flbsbn.zsf31ayvobt.dns.navy
  - type: domain
    value: guidetx.suredoc.net
  - type: domain
    value: mareqsutxn.v6.navy
  - type: domain
    value: mj9tqlj86sz.dns.navy
  - type: domain
    value: ncloud.casacam.net
  - type: domain
    value: ndoc.ncloud.casacam.net
  - type: domain
    value: nid-log-pl.2u9f.2usrmmwwduz.dns.navy
  - type: domain
    value: nid-token.tkho.mareqsutxn.v6.navy
  - type: domain
    value: nidmois.p0fx8.923h5qvvzq2.v6.navy
  - type: domain
    value: nidsign.mylogisoft.com
  - type: domain
    value: ninvoice.parentinvolvement.in
  - type: domain
    value: ninvoice.taxcloud.kro.kr
  - type: domain
    value: p0fx8.923h5qvvzq2.v6.navy
  - type: domain
    value: pol-go-nid.6td4w.mj9tqlj86sz.dns.navy
  - type: domain
    value: pol-go-nid.flbsbn.zsf31ayvobt.dns.navy
  - type: domain
    value: taxcloud.kro.kr
  - type: domain
    value: tkho.mareqsutxn.v6.navy
  - type: domain
    value: toxcloud.dns.army
  - type: domain
    value: vvg1ylsb4a7.dns.navy
  - type: domain
    value: zsf31ayvobt.dns.navy
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/f20c6823363a1cd1b330b4b4a9891beec7f27aec
  - type: domain
    value: pantofr.cyou
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/e202683c7f0d46980803d6b05a038f2b819a43b2
  - type: domain
    value: wpcdnwsswp.com
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/581025fa091e6a2594d7a849980caa94b438a982
  - type: url
    value: https://x.com/Malwarehunterr/status/2057196561172689389
  - type: domain
    value: ainalapitool.online
  - type: domain
    value: asifapi.xyz
  - type: domain
    value: biplobapi.xyz
  - type: domain
    value: hasanapi.xyz
  - type: domain
    value: jasimapi.xyz
  - type: domain
    value: lahinapi.xyz
  - type: domain
    value: milonapi.xyz
  - type: domain
    value: ronyapi.xyz
  - type: domain
    value: sohanapi.xyz
  - type: domain
    value: sohelapitool.online
  - type: domain
    value: tmrlapi.xyz
  - type: domain
    value: toolapipanel.online
  - type: domain
    value: call-video.website
  - type: domain
    value: due-chat.call-video.website
  - type: domain
    value: due-live-call.online
  - type: domain
    value: due.live-video-call.my.id
  - type: domain
    value: duolivecall-googel.com
  - type: domain
    value: ecortbabylon.site
ioc_counts:
  domain: 44
  url: 6
rules:
  - title: Detect Connections to Kimsuky DNS Navy Domains
    description: Detects connections to domains ending with dns.navy, potentially related to APT Kimsuky activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.004
    data_sources:
      - dns_query
  - title: Detect FakeApp Domains
    description: Detects connections to domains associated with FakeApp campaign based on domain naming conventions.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - dns_query
  - title: Detect Connection to Pantofr Domain
    description: Detects connections to the pantofr.cyou domain associated with Lummac2
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - dns_query
rules_count: 3
---

This threat brief is based on a Maltrail feed update from 2026-05-20 which identifies network IOCs associated with multiple threat actors and campaigns. The identified actors include APT Kimsuky, a suspected North Korean threat group known for espionage and cybercrime, along with campaigns attributed to Lummac2, MagentoCore, and FakeApp. The IOCs consist primarily of domains that are likely used for command and control, phishing, or malware distribution. This information is relevant for defenders seeking to identify and block malicious network traffic related to these campaigns. The domains associated with FakeApp suggest potential phishing or social engineering campaigns.

## Attack Chain

1.  **Initial Compromise:** The attack chain likely starts with phishing emails or social engineering tactics to lure victims to visit malicious websites.
2.  **Domain Resolution:** Victims click on links within phishing emails, resolving malicious domains (e.g., `duolivecall-googel.com`) associated with the campaigns.
3.  **Payload Delivery:** Upon visiting the malicious domain, the victim may be prompted to download a malicious application or document containing malware.
4.  **Command and Control (C2) Communication:** The malware establishes communication with command and control servers using domains such as `2u9f.2usrmmwwduz.dns.navy` (for APT Kimsuky) or `pantofr.cyou` (for Lummac2) to receive instructions.
5.  **Data Exfiltration:** The compromised system begins exfiltrating sensitive data to attacker-controlled infrastructure.
6.  **Lateral Movement:** Depending on the malware and the actor's objectives, lateral movement may occur to compromise additional systems within the network.

## Impact

Successful attacks leveraging these IOCs could result in data theft, system compromise, espionage, or financial loss. Victims may include individuals targeted by FakeApp scams, or organizations compromised by APT Kimsuky for espionage purposes. The MagentoCore campaign suggests potential targeting of e-commerce platforms for financial gain through skimming or data theft.

## Recommendation

*   Block the domains listed in the IOC table at the DNS resolver to prevent communication with malicious infrastructure.
*   Deploy the Sigma rules in this brief to your SIEM and tune for your environment.
*   Monitor network traffic for connections to the domains associated with APT Kimsuky, Lummac2, MagentoCore, and FakeApp.
