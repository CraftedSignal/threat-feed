---
title: Maltrail IOCs for ImminentRAT and EK_ClearFake Campaigns
slug: 2026-05-maltrail-iocs
description: This brief covers newly published Maltrail IOCs, including domains associated with EK_ClearFake and an IP address and domains associated with ImminentRAT, potentially indicating ongoing malicious activity.
date: "2026-05-06T12:00:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - imminentrat
  - ek_clearfake
  - malware
  - rat
  - phishing
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
  - https://www.circl.lu/doc/misp/feed-osint/18fe8d57-6f89-4001-9500-7b26c0f50c8b.json
iocs:
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/6668708e0fd58004129536b2f421c2eaaa37f10e
  - type: url
    value: https://x.com/Fact_Finder03/status/2051952424609628206
  - type: url
    value: https://www.virustotal.com/gui/file/9f93e3fde12dfd6ec269e082e4429b562698aca4122c05111168bd7345b49f94/detection
  - type: url
    value: https://www.virustotal.com/gui/file/ba057c29b899fff8770dbccc39c533d2de294acc5f0ddeb2fc4f7aea2057e92b/detection
  - type: url
    value: https://www.virustotal.com/gui/file/d6baf65de9bf177fae9cc926267295c6efda60979ca1d3261dcbeeead0f714b8/detection
  - type: ip
    value: 79.130.189.207
  - type: domain
    value: trojandev.ddns.net
  - type: domain
    value: trojandev.servehttp.com
  - type: domain
    value: trojandev2.servehttp.com
  - type: domain
    value: trojandev20.servehttp.com
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/d10e877cc29d6f2fbd59fc1da20480e2246014f0
  - type: domain
    value: nanobanano.baby
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/b9e9f30f096b6bea936ead2a71b43ace1827772c
  - type: domain
    value: 1dorelax.surf
  - type: domain
    value: 1zorelix.surf
  - type: domain
    value: 2zorelin.surf
  - type: domain
    value: 3zavlore.surf
  - type: domain
    value: 4dapt3-node.pavlore9.surf
  - type: domain
    value: 4dorexal.surf
  - type: domain
    value: 5bb2q4fr.izyob7rickets.digital
  - type: domain
    value: 5parr-forge.torex5lin.surf
  - type: domain
    value: 6toralex.surf
  - type: domain
    value: 7toralex.lat
  - type: domain
    value: 8dorexin.surf
  - type: domain
    value: 9sgsurs.vexon3ar.surf
  - type: domain
    value: 9toravex.surf
  - type: domain
    value: a1ig-vector.vexon3ar.surf
  - type: domain
    value: actsdks.surf
  - type: domain
    value: alig9-trail.1dorelax.surf
  - type: domain
    value: alt-b1oo.xamir2el.surf
  - type: domain
    value: apidoc.1zorelix.surf
  - type: domain
    value: apidoc.3zavlore.surf
  - type: domain
    value: apidocs.2zorelin.surf
  - type: domain
    value: apidocs.fewhtml.surf
  - type: domain
    value: apidocs.nodespit.surf
  - type: domain
    value: apidocs.technovortexhub.surf
  - type: domain
    value: apiops.sori7xen.surf
  - type: domain
    value: apiops.sorix2el.surf
  - type: domain
    value: apiopss.lorex7in.surf
  - type: domain
    value: apiopss.ultrashiftnet.surf
  - type: domain
    value: apiopss.zooblob.surf
  - type: domain
    value: appbox.6toralex.surf
  - type: domain
    value: appboxs.9toravex.surf
  - type: domain
    value: appboxs.actsdks.surf
  - type: domain
    value: appboxs.digitalcloudnet.surf
  - type: domain
    value: appboxs.tonmixin.surf
  - type: domain
    value: appsrc.sori7xen.surf
  - type: domain
    value: appsrc.sorix2el.surf
  - type: domain
    value: appsrch.lorex7in.surf
  - type: domain
    value: appsrch.ultrashiftnet.surf
ioc_counts:
  domain: 42
  ip: 1
  url: 7
rules:
  - title: Detect ImminentRAT C2 Beacon
    description: Detects network connections to known ImminentRAT command and control servers.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect EK_ClearFake Domain Access
    description: Detects DNS queries to domains associated with the EK_ClearFake campaign.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

This threat brief is based on Maltrail IOCs published on 2026-05-06, highlighting potential malicious activity related to two distinct campaigns: EK_ClearFake and ImminentRAT. The EK_ClearFake campaign involves a large number of newly registered domains, often using similar naming patterns and hosting various fake services. ImminentRAT indicators include a specific IP address and a few domains resolving to it. These indicators may represent command-and-control infrastructure, malware distribution points, or phishing sites. Defenders should investigate network traffic and DNS queries for these IOCs to identify potentially compromised systems or ongoing attacks.

## Attack Chain

This attack chain is inferred based on the nature of the identified IOCs and common attack patterns associated with RATs and fake services.

1.  **Initial Access:** User visits a compromised website or falls victim to a social engineering attack (e.g., phishing email).
2.  **Delivery:** Malicious payload (e.g., ImminentRAT installer) is delivered to the victim's machine via drive-by download or as an attachment.
3.  **Installation:** The ImminentRAT malware is installed on the victim's system, establishing persistence.
4.  **Command and Control:** The ImminentRAT malware connects to the C2 server (79.130.189.207 or trojandev.ddns.net) to receive instructions.
5.  **Privilege Escalation:** The malware attempts to escalate privileges on the compromised system to gain higher-level access.
6.  **Data Exfiltration:** Sensitive data is stolen from the victim's system and transmitted to the attacker's infrastructure.
7.  **Lateral Movement:** Attackers use the compromised system as a launchpad to move laterally within the network, compromising additional systems.
8.  **Final Objective:** The ultimate goal could include data theft, financial fraud, espionage, or disruption of services.

For EK_ClearFake, the domains are likely used in phishing or scams, attempting to steal credentials or lure victims into fraudulent transactions.

## Impact

Successful exploitation can lead to data breaches, financial loss, reputational damage, and system compromise. If ImminentRAT is successfully deployed, attackers could gain complete control over the infected system, enabling them to steal sensitive information, install additional malware, or use the system as a bot in a larger attack. The EK_ClearFake domains may be used in phishing campaigns, leading to credential theft and account compromise.

## Recommendation

*   Monitor network traffic and DNS queries for connections to the IOCs listed in this brief, including the ImminentRAT IP address `79.130.189.207` and domains such as `trojandev.ddns.net`.
*   Block the C2 domains associated with ImminentRAT (`trojandev.ddns.net`, `trojandev.servehttp.com`, `trojandev2.servehttp.com`, `trojandev20.servehttp.com`) at the DNS resolver.
*   Implement web filtering to block access to the domains associated with EK_ClearFake (e.g., `nanobanano.baby`, `1dorelax.surf`, etc.)
*   Deploy the Sigma rule `Detect ImminentRAT C2 Beacon` to your SIEM to identify potential ImminentRAT infections.
*   Deploy the Sigma rule `Detect EK_ClearFake Domain Access` to your SIEM to identify potential phishing attempts.
