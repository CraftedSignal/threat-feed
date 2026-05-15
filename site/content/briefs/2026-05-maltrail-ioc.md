---
title: Maltrail IOC Feed Update - 2026-05-15
slug: 2026-05-maltrail-ioc
description: This brief summarizes a Maltrail IOC feed update on 2026-05-15, containing indicators associated with APT_Kimsuky, CyberstrikeAI, Android_Joker, Sectoprat, EK_Landupdate808, and MagentoCore campaigns involving suspicious domains and IP addresses.
date: "2026-05-15T10:08:15Z"
type: threat
types:
  - threat
severities:
  - medium
actors:
  - APT_Kimsuky
tags:
  - maltrail
  - ioc
  - threat-intelligence
vendors:
  - GitHub
products:
  - github.com
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
references:
  - https://www.circl.lu/doc/misp/feed-osint/a56de1cb-027a-4b49-be18-e0cff3ba8118.json
iocs:
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/b7cf24d5696efc82affb75f5e4093d316db8caa8
  - type: domain
    value: mhjwsf.reverifyblogmid19s.dns.army
  - type: domain
    value: naveblogedit33s.dns.army
  - type: domain
    value: qxnhdalc.naveblogedit33s.dns.army
  - type: domain
    value: reverifyblogmid0s.dns.army
  - type: domain
    value: reverifyblogmid19s.dns.army
  - type: domain
    value: uhmymkd.reverifyblogmid0s.dns.army
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/425493bcf541d6ddc3aa257accf29b5474227c6d
  - type: ip
    value: 111.231.63.109
  - type: ip
    value: 118.126.95.156
  - type: ip
    value: 118.145.227.8
  - type: ip
    value: 134.122.153.78
  - type: ip
    value: 138.249.133.120
  - type: ip
    value: 192.248.172.82
  - type: ip
    value: 203.83.10.114
  - type: ip
    value: 80.96.109.59
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/3561cc7ff2bf2fade01d79905ad0435f3708f7e9
  - type: domain
    value: mixcar.store
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/6e2924c45ecb373aca5d50ff8a068f55f71b43a6
  - type: ip
    value: 103.246.144.201
  - type: ip
    value: 191.101.80.211
  - type: ip
    value: 217.60.98.113
  - type: ip
    value: 31.76.251.134
  - type: ip
    value: 45.76.86.194
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/89891505ba39c926febf4707e1f35afed681332b
  - type: domain
    value: titchell.lol
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/c3eb79792e3e259d1d47c7b233fe87e0b81c8eaf
  - type: domain
    value: 5q.reports-cdn.com
  - type: domain
    value: 5v.east-report.com
  - type: domain
    value: q2.cdn-hs.com
  - type: domain
    value: tt.stat-hs.com
  - type: url
    value: https://api.github.com/repos/stamparm/maltrail/commits/9baa4673ad2ca11713e206666f8debe1b085be0a
  - type: domain
    value: 20.socket-cdn.com
  - type: domain
    value: 28.wsrequest.com
  - type: domain
    value: 2fabmoenroll.com
  - type: domain
    value: 34.socket-wss.com
  - type: domain
    value: 34.wss-socket.com
  - type: domain
    value: 3h.ws-request.com
  - type: domain
    value: 3p.request-ws.net
  - type: domain
    value: 4p.cdn-connect.com
  - type: domain
    value: 5j.auth-securi.com
  - type: domain
    value: 5k.request-cdn.com
  - type: domain
    value: 5r.auth-securi.net
  - type: domain
    value: 5t.connect-wss.com
  - type: domain
    value: 5t.wss-connect.com
  - type: domain
    value: 6g.protect-wss.com
  - type: domain
    value: 6i.llvechatinc.com
  - type: domain
    value: 7o.analityc-cdn.com
  - type: domain
    value: 7r.llve-chatinc.com
  - type: domain
    value: 9e5b43cb6413.houseofcards.store
ioc_counts:
  domain: 30
  ip: 13
  url: 7
rules:
  - title: Detect Connections to CyberstrikeAI IPs
    description: Detects network connections to IP addresses associated with CyberstrikeAI activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Connections to Android_Joker Domain
    description: Detects network connections to the domain associated with Android_Joker malware.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1573.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Connections to EK_Landupdate808 Domain
    description: Detects network connections to the domain associated with EK_Landupdate808 activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1573.001
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

This threat brief summarizes the indicators of compromise (IOCs) published in the Maltrail feed on 2026-05-15. The IOCs are associated with multiple campaigns including APT_Kimsuky, CyberstrikeAI, Android_Joker, Sectoprat, EK_Landupdate808, and MagentoCore. The feed contains network-based IOCs such as domains and IP addresses. These indicators can be used to detect and block malicious network traffic related to these campaigns. The varied nature of the associated campaigns suggests a wide range of potential threats, from mobile malware to e-commerce platform attacks, necessitating a broad monitoring approach. The update highlights the continuous need for up-to-date threat intelligence for effective network security.

## Attack Chain

This Maltrail feed provides indicators for multiple different campaigns, and so a single attack chain is not possible to construct. However, based on the names of the malware families, we can assume some possible attack chains:

**MagentoCore (Possible Attack Chain)**

1.  The attacker identifies a Magento e-commerce platform with vulnerabilities.
2.  The attacker injects malicious JavaScript code into the Magento store, potentially through a compromised plugin or theme.
3.  The injected JavaScript code loads from one of the listed domains (e.g., `5q.reports-cdn.com`).
4.  The script captures sensitive customer data such as credit card information and login credentials.
5.  The stolen data is exfiltrated to the attacker's server via the compromised domain infrastructure.
6.  The attacker uses the stolen data for financial fraud or identity theft.

**Android_Joker (Possible Attack Chain)**

1.  The attacker develops a malicious Android application and publishes it on a third-party app store.
2.  The user downloads and installs the malicious Android application (disguised as a legitimate app).
3.  The malicious application requests intrusive permissions like SMS access and contact list access.
4.  The application communicates with a command-and-control server like `mixcar.store`.
5.  The malware subscribes the user to premium SMS services without their knowledge.
6.  The attacker profits from the fraudulent subscriptions.

## Impact

The impact of these IOCs depends on the specific campaign they are associated with. For example, MagentoCore attacks can lead to financial losses and reputational damage for e-commerce businesses, as well as identity theft for customers. Android_Joker malware can result in financial fraud and privacy breaches for mobile users. APT_Kimsuky campaigns typically target political and strategic intelligence, causing damage to national security and international relations. The number of potential victims is difficult to determine, but given the widespread use of Magento and Android devices, the potential impact is significant.

## Recommendation

*   Block the listed domains in your DNS resolver and web proxy to prevent communication with known malicious infrastructure, using the IOCs provided (domains).
*   Block the listed IP addresses in your firewall to prevent network connections to known malicious hosts, using the IOCs provided (IP addresses).
*   Monitor web server logs for requests to the listed domains to identify potentially compromised systems that may be attempting to communicate with malicious infrastructure.
*   Monitor network traffic for connections to the listed IP addresses to identify potentially compromised systems.
*   Investigate any systems that have communicated with the listed domains or IP addresses for signs of compromise.
