---
title: macOS DNS Request for IP Lookup Service via Unsigned Binary
slug: 2024-01-macos-unsigned-ip-lookup
description: An unsigned or untrusted binary on macOS is performing DNS requests for IP lookup services to determine the system's external IP address, which is commonly used by malware for reconnaissance before establishing C2 connections.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - macos
  - dns
  - reconnaissance
  - unsigned_binary
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/discovery_dns_request_for_ip_lookup_service.toml
iocs:
  - type: domain
    value: api.ipify.org
  - type: domain
    value: ipinfo.io
  - type: domain
    value: ip-api.com
  - type: domain
    value: ipwho.is
  - type: domain
    value: checkip.dyndns.org
  - type: domain
    value: api.npoint.io
  - type: domain
    value: whatismyip.akamai.com
  - type: domain
    value: bot.whatismyipaddress.com
  - type: domain
    value: ifcfg.me
  - type: domain
    value: ifconfig.me
  - type: domain
    value: ident.me
  - type: domain
    value: ipof.in
  - type: domain
    value: ip.tyk.nu
  - type: domain
    value: ipwhois.app
  - type: domain
    value: freeipapi.com
  - type: domain
    value: icanhazip.com
  - type: domain
    value: curlmyip.com
  - type: domain
    value: wgetip.com
  - type: domain
    value: eth0.me
  - type: domain
    value: ipecho.net
  - type: domain
    value: ip.appspot.com
  - type: domain
    value: api.myip.com
  - type: domain
    value: geoiptool.com
  - type: domain
    value: api.2ip.ua
  - type: domain
    value: api.ip.sb
  - type: domain
    value: checkip.amazonaws.com
  - type: domain
    value: wtfismyip.com
  - type: domain
    value: freegeoip.net
  - type: domain
    value: freegeoip.app
  - type: domain
    value: myip.ipip.net
  - type: domain
    value: geoplugin.net
  - type: domain
    value: myip.dnsomatic.com
  - type: domain
    value: www.geoplugin.net
  - type: domain
    value: api64.ipify.org
  - type: domain
    value: ip4.seeip.org
  - type: domain
    value: '*.geojs.io'
  - type: domain
    value: portmap.io
  - type: domain
    value: api.db-ip.com
  - type: domain
    value: geolocation-db.com
  - type: domain
    value: inet-ip.info
  - type: domain
    value: httpbin.org
  - type: domain
    value: myip.opendns.com
ioc_counts:
  domain: 42
rules:
  - title: Detect DNS Request for IP Lookup Service via Unsigned Binary
    description: Detects when a DNS request is made for an IP lookup service by an unsigned or untrusted binary on macOS, commonly used for reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1016
      - T1016.001
    data_sources:
      - dns_query
      - macos
  - title: Detect Unsigned Process Executing Network Activity
    description: Detects an unsigned process making network connections.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
    techniques:
      - T1071
    data_sources:
      - network_connection
      - macos
rules_count: 2
---

This activity detects when a DNS request is made for an IP lookup service to determine the external IP address of a macOS system via an unsigned or untrusted binary. This technique is frequently employed by malware for reconnaissance purposes prior to establishing command and control (C2) communications. The detection focuses on identifying DNS queries from processes lacking valid code signatures, which can indicate the presence of malicious or suspicious software. A typical pattern involves an unsigned Mach-O or script resolving domains like api.ipify.org or ipinfo.io immediately after execution, followed by outbound beacons. This activity is important to detect as it is an early stage indicator of compromise, allowing defenders to disrupt potential malware before further malicious actions can be performed.

## Attack Chain

1. A malicious or unwanted application is executed on a macOS system, often without a valid code signature or trusted signature.
2. The application attempts to determine the system's external IP address to potentially tailor further actions.
3. To discover the external IP, the application performs a DNS lookup for a known IP lookup service domain (e.g., api.ipify.org, ipinfo.io).
4. The DNS query is resolved, providing the application with the system's external IP address.
5. The application may then use the IP address to determine the system's geolocation or other network-related information.
6. Based on the gathered information, the application may select a command and control (C2) server or adjust its behavior.
7. The application initiates a connection to the selected C2 server, potentially downloading further malicious payloads or receiving instructions.
8. Finally, malware establishes C2 communication and starts exfiltrating data or performing other malicious actions.

## Impact

Compromised systems can lead to data exfiltration, unauthorized access, and further propagation of malware within the network. Successful reconnaissance allows attackers to tailor their attacks, potentially evading detection and maximizing impact. While the severity is medium, early detection of this activity is crucial to prevent more significant damage. The absence of a valid code signature increases the likelihood of the process being malicious.

## Recommendation

*   Deploy the Sigma rule "Detect DNS Request for IP Lookup Service via Unsigned Binary" to your SIEM and tune for your environment to detect unsigned binaries querying for IP lookup services.
*   Investigate any alerts generated by the Sigma rule, focusing on the process's origin, parent processes, and subsequent network activity.
*   Block the observed IP-lookup domains listed in the IOC table at the DNS resolver to prevent further reconnaissance.
*   Isolate affected macOS hosts from the network if unsigned processes continue to resolve IP-lookup domains or initiate new outbound connections.
*   Acquire and analyze any unsigned binaries identified by the detection rule to confirm intent and scope of compromise.
