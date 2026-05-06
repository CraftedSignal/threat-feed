---
title: Suspicious Windows Processes Querying Public IP Discovery Services via DNS
slug: 2024-01-public-ip-discovery
description: Detection of suspicious Windows processes using DNS queries to public IP address lookup services can indicate reconnaissance activity or command and control preparation by threat actors.
date: "2024-01-09T17:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - discovery
  - command-and-control
  - windows
  - public-ip
vendors:
  - Elastic
  - SentinelOne
  - Crowdstrike
products:
  - Elastic Defend
  - SentinelOne Cloud Funnel
  - Crowdstrike
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
  - title: Suspicious Processes Querying Public IP Discovery Services
    description: Detects suspicious Windows processes querying known public IP address lookup services via DNS.
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
  - title: Suspicious Processes Code Signature Check
    description: Detects suspicious processes that are unsigned or signed by untrusted authority making DNS requests.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

This detection identifies instances where suspicious Windows processes use DNS queries to resolve well-known public IP address lookup services. Attackers may leverage these services to determine the external IP address of a compromised host, which is a common reconnaissance step before further malicious activity. This activity is often associated with initial access, privilege escalation, or establishing command and control channels. The processes monitored include scripting engines (powershell.exe, wscript.exe), installers (msiexec.exe), and other LOLBins (bitsadmin.exe, rundll32.exe) often abused by threat actors. The rule also flags unsigned or untrusted executables making these DNS requests. Defenders should monitor for this behavior to identify potentially compromised systems early in the attack chain. The detection logic is derived from Elastic detection rule 642ce354-4252-4d43-80c9-6603f16571c1.

## Attack Chain

1. A user inadvertently executes a malicious file or script (e.g., via phishing or drive-by download).
2. The malicious code executes using a scripting engine like PowerShell or a LOLBin such as mshta.exe.
3. The executing process initiates a DNS query to resolve a public IP address lookup service (e.g., api.ipify.org, icanhazip.com).
4. The DNS query resolves successfully, providing the external IP address of the host.
5. The malicious process stores the external IP address for later use.
6. The attacker uses the discovered external IP address to identify the target for subsequent attacks or to establish a command and control channel.
7. The compromised host communicates with a C2 server, providing system information, including the external IP address.
8. The attacker leverages the C2 channel to deploy additional malware, escalate privileges, or exfiltrate data.

## Impact

Successful exploitation can lead to an attacker gaining knowledge of the target's external IP address, enabling them to perform reconnaissance, launch targeted attacks, and potentially compromise the entire network. If an attacker gains access to the external IP they can perform scans for exposed services and devices, this can be used to gain an initial foothold in the network. There is no specific victim count available, but this type of reconnaissance is common across various sectors.

## Recommendation

*   Deploy the Sigma rule `Suspicious Processes Querying Public IP Discovery Services` to your SIEM and tune for your environment.
*   Block the C2 domains listed in the IOC table at the DNS resolver.
*   Enable Sysmon Event ID 22 (DNS Query) logging to ensure proper visibility for the detections in this brief.
*   Investigate any alerts generated by the Sigma rule to determine the legitimacy of the DNS queries and the associated processes.
*   Monitor for network connections originating from processes that have queried public IP address services.
