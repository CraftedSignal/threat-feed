---
title: Suspicious Process Performing Public IP Address Discovery via DNS
slug: 2024-01-public-ip-discovery
description: Detection of suspicious Windows processes using DNS queries to determine the external IP address, potentially indicating reconnaissance or preparation for command and control activity.
date: "2024-01-03T18:23:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - discovery
  - command-and-control
  - windows
  - dns
vendors:
  - Elastic
  - Microsoft
products:
  - Elastic Defend
  - Windows Defender
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1016
    technique_name: System Network Configuration Discovery
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://attack.mitre.org/techniques/T1016/
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/discovery_host_public_ip_address_lookup.toml
iocs:
  - type: domain
    value: ip-api.com
  - type: domain
    value: checkip.dyndns.org
  - type: domain
    value: api.ipify.org
  - type: domain
    value: api.ipify.com
  - type: domain
    value: whatismyip.akamai.com
  - type: domain
    value: bot.whatismyipaddress.com
  - type: domain
    value: ifcfg.me
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
    value: '*portmap.io'
  - type: domain
    value: api.db-ip.com
  - type: domain
    value: geolocation-db.com
  - type: domain
    value: httpbin.org
  - type: domain
    value: myip.opendns.com
ioc_counts:
  domain: 36
rules:
  - title: Suspicious Process Public IP Discovery via DNS Query
    description: Detects suspicious processes querying public IP address lookup services via DNS.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - discovery
    techniques:
      - T1016
    data_sources:
      - dns_query
      - windows
  - title: Suspicious Process Public IP Discovery via DNS Query (Unsigned)
    description: Detects unsigned processes querying public IP address lookup services via DNS.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
      - discovery
    techniques:
      - T1016
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

This rule identifies Windows processes querying known public IP address lookup services through DNS. This behavior is often associated with reconnaissance activities, where attackers attempt to determine the external IP address of a compromised system before proceeding with further malicious actions. Attackers may use this information to tailor their attacks, establish command and control channels, or exfiltrate data. The rule focuses on detecting queries originating from processes such as `MSBuild.exe`, `mshta.exe`, `powershell.exe`, and others that are commonly abused by attackers. It also flags unsigned processes, or those signed by untrusted entities, as well as processes running from user-writable directories, increasing the likelihood of detecting malicious activity. The rule excludes queries originating from Windows Defender to reduce false positives. This activity matters to defenders because successful discovery of the public IP can aid attackers in further exploitation and lateral movement.

## Attack Chain

1.  A user inadvertently downloads and executes a malicious payload (e.g., via phishing or drive-by download).
2.  The malicious payload, disguised as a legitimate application or script, executes on the compromised system.
3.  The executed payload spawns a suspicious process such as `powershell.exe`, `mshta.exe`, or `rundll32.exe`.
4.  The spawned process initiates a DNS query to a known public IP address lookup service (e.g., `api.ipify.org`, `icanhazip.com`).
5.  The DNS query resolves to the IP address of the lookup service, providing the compromised host's external IP address.
6.  The malicious process may then use the obtained IP address to establish a command and control (C2) channel with a remote server.
7.  The attacker uses the C2 channel to deliver further instructions, exfiltrate data, or deploy additional payloads.
8.  The attacker may then perform lateral movement within the network using the compromised system as a pivot point.

## Impact

A successful attack may result in the compromise of sensitive data, the establishment of a persistent foothold within the network, and lateral movement to other systems. Attackers can use the obtained public IP address to tailor their attacks, bypass security measures, or identify targets within the network. Organizations may experience data breaches, financial losses, and reputational damage. The number of victims and the extent of the damage vary depending on the sophistication of the attacker and the effectiveness of the organization's security controls.

## Recommendation

*   Deploy the "Suspicious Process Public IP Discovery via DNS Query" Sigma rule to your SIEM and tune it to your environment.
*   Monitor DNS query logs for any suspicious processes querying the IOC domains (e.g., `api.ipify.org`, `icanhazip.com`) listed in this brief.
*   Investigate any alerts triggered by the Sigma rule, focusing on the process lineage, network connections, and any follow-on activity.
*   Block the C2 domains listed in the IOC table at the DNS resolver to disrupt attacker communications.
*   Enable Sysmon DNS query logging (Event ID 22) to improve visibility into DNS activity on Windows endpoints.
