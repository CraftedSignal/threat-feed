---
title: Linux External IP Discovery via Curl
slug: 2026-07-linux-curl-external-ip-discovery
description: This brief details the detection of Linux processes utilizing `curl` to contact known public IP address lookup web services, a common post-exploitation technique employed by malware and adversaries to ascertain a host's internet-facing IP, impacting reconnaissance and command-and-control tailoring.
date: "2026-07-06T14:29:23Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - discovery
  - linux
  - endpoint
  - reconnaissance
  - curl
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
    evidence: This rule flags a Linux process that uses curl to contact public IP lookup sites, a common way malware learns the host’s internet-facing address.
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
    value: .geojs.io
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
    description: Detects Linux processes making a curl request to a known public IP address lookup web service, a common behavior in malware for external IP discovery.
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

This threat brief focuses on a common post-exploitation tactic where adversaries leverage the `curl` utility on Linux systems to discover the external IP address of a compromised host. This activity is frequently observed in malware and during manual attacker reconnaissance. After gaining initial access and shell capabilities, an attacker will often query public IP lookup services (e.g., ifconfig.me, ipify.org) to understand the network context of their target. This information helps them determine if the system is behind a NAT or cloud infrastructure, verify outbound connectivity, and subsequently tailor their command-and-control (C2) communications or decide on further actions. While individual instances of this activity might be benign (e.g., administrator troubleshooting), its occurrence post-compromise is a strong indicator of malicious intent, making detection crucial for identifying adversary presence and preventing subsequent stages of an attack.

## Attack Chain

1.  **Initial Access**: An attacker successfully compromises a Linux system, often gaining shell access through a vulnerability exploitation, credential compromise, or malicious payload execution.
2.  **Execution of `curl`**: The attacker or malware executes the `curl` command-line utility from a shell or script.
3.  **External IP Discovery**: `curl` is directed to contact a known public IP address lookup web service (e.g., `icanhazip.com`, `api.ipify.org`).
4.  **Network Context Assessment**: The returned public IP address is used by the attacker to understand the system's outbound network configuration, including whether it's behind a NAT or within cloud infrastructure.
5.  **Decision Point**: Based on the discovered IP, the attacker makes decisions regarding subsequent actions, such as configuring C2 channels, performing further reconnaissance, or exfiltrating data.
6.  **Follow-on Activity**: The attacker proceeds with activities like establishing persistent C2, deploying additional tools, or initiating lateral movement, leveraging the gathered network intelligence.

## Impact

While the act of discovering an external IP address itself does not cause direct damage, its successful execution provides crucial intelligence to an adversary, significantly impacting the efficacy of subsequent attack stages. If this reconnaissance goes undetected, attackers can better adapt their tactics for command-and-control, data exfiltration, and lateral movement, potentially leading to widespread compromise, data breaches, or denial of service. The impact includes the successful continuation of the attack chain, making the system more vulnerable to deeper compromise and enabling attackers to bypass network defenses specifically tailored to internal IP schemes.

## Recommendation

*   Deploy the Sigma rule "Linux External IP Address Discovery via Curl" to your SIEM and tune for your environment.
*   Configure endpoint telemetry to capture process creation events, including `process.name` and `process.command_line`, especially for `curl` executions, as required by the detection rule.
*   Implement network egress filtering to restrict outbound `curl` access to only explicitly approved destinations, blocking the domains listed in the IOCs where not legitimately required.
*   Review the `process.parent.name` and `process.parent.executable` fields in your logs to identify legitimate scripts or services that might trigger the rule and add them to the rule's filter block as appropriate.
*   Monitor for `curl` activity from unusual parent processes or unexpected directories (`/tmp`, `/var/tmp`, `/dev/shm`) as highlighted in the rule's query.
