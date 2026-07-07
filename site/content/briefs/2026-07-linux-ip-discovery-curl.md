---
title: Linux External IP Address Discovery via Curl
slug: 2026-07-linux-ip-discovery-curl
description: Malware and threat actors on Linux systems utilize the `curl` command to query public web services for external IP address discovery, a reconnaissance technique (T1016) that can precede further C2 establishment or targeted attacks.
date: "2026-07-03T15:15:13Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - linux
  - reconnaissance
vendors:
  - Elastic
  - SentinelOne
products:
  - Elastic Defend
  - SentinelOne Cloud Funnel
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
    evidence: Detects applications making a curl request to a known public IP address lookup web service. Malware tends to perform this action to assess potential targets.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/discovery_curl_external_ip_discovery.toml
iocs:
  - type: domain
    value: ip-api.com
  - type: domain
    value: checkip.dyndns.org
  - type: domain
    value: api.ipify.org
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
    value: ipinfo.io
  - type: domain
    value: checkip.amazonaws.com
  - type: domain
    value: wtfismyip.com
  - type: domain
    value: freegeoip.net
  - type: domain
    value: freegeoip.app
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
    value: httpbin.org
  - type: domain
    value: myip.opendns.com
  - type: domain
    value: ipv4.icanhazip.com
  - type: domain
    value: ipv6.icanhazip.com
ioc_counts:
  domain: 38
rules:
  - title: Linux External IP Address Discovery via Curl
    description: Detects the execution of 'curl' on Linux systems to query known public web services for external IP address discovery, a common reconnaissance technique used by malware.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1016
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This brief details a common reconnaissance technique employed by malware and threat actors operating on Linux systems: the discovery of a compromised host's external IP address using the `curl` utility. Attackers leverage `curl` to send requests to various public IP lookup services (e.g., ip-api.com, ifconfig.me), which then return the external IP address of the originating request. This action is crucial for attackers to understand their network egress point, configure command and control (C2) channels, or to tailor subsequent attack phases based on the victim's geographical or network location. The detection focuses on identifying `curl` executions where the command line arguments contain known domain patterns for these IP lookup services. This activity, while benign in some legitimate contexts, is frequently observed as a post-exploitation step, making it a valuable indicator of potential malicious activity.

## Attack Chain

1.  **Initial Compromise**: An attacker gains initial access to a Linux system through various means (e.g., exploiting a vulnerability, phishing, weak credentials).
2.  **Establish Foothold**: The attacker establishes persistence and ensures continued access to the compromised system.
3.  **Process Execution**: The attacker executes the `curl` utility, often from a suspicious parent process or unusual directory.
4.  **External IP Lookup**: `curl` is directed to query a known public web service (e.g., `api.ipify.org`, `icanhazip.com`) to retrieve the host's external IP address.
5.  **Information Gathering**: The output of the `curl` command, containing the external IP, is captured by the attacker.
6.  **Reconnaissance/C2 Setup**: The obtained external IP address is then used by the attacker for further reconnaissance, establishing a stable command and control (C2) channel, or preparing for subsequent stages of their operation.

## Impact

Successful external IP address discovery by an attacker, while not directly damaging, is a critical precursor to more impactful activities. It provides the adversary with essential network context, enabling them to bypass network segmentation, configure firewalls or routing for C2 communications, or identify targets within the same external network space. This can lead to subsequent data exfiltration, deployment of additional malware, or lateral movement within the victim's broader infrastructure, significantly increasing the risk of financial loss, data breach, or operational disruption.

## Recommendation

*   Deploy the provided Sigma rule "Linux External IP Address Discovery via Curl" to your SIEM/EDR to detect this specific reconnaissance technique.
*   Ensure process creation logging is enabled for `curl` on Linux endpoints, as required for the detection rule to function effectively.
*   Block connections to the listed public IP lookup domains (e.g., `ip-api.com`, `api.ipify.org`, `icanhazip.com`) at the network perimeter where appropriate to limit an attacker's ability to perform this reconnaissance.
*   Investigate alerts generated by the "Linux External IP Address Discovery via Curl" rule, focusing on the parent process and execution path of `curl` for signs of compromise.
