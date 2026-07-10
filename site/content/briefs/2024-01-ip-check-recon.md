---
title: Windows Processes Gathering Network Information via IP Check Web Services
slug: 2024-01-ip-check-recon
description: Detection of Windows processes using IP check web services for reconnaissance, a behavior commonly associated with malware like Trickbot, by monitoring DNS queries.
date: "2024-01-03T15:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - network-reconnaissance
  - malware-behavior
  - windows
vendors:
  - Microsoft
products:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Reconnaissance
    technique_id: T1590
    technique_name: Gather Victim Network Information
references:
  - https://app.any.run/tasks/a6f2ffe2-e6e2-4396-ae2e-04ea0143f2d8/
iocs:
  - type: domain
    value: wtfismyip.com
  - type: domain
    value: ipinfo.io
  - type: domain
    value: api.ipify.org
  - type: domain
    value: icanhazip.com
  - type: domain
    value: ip.anysrc.com
  - type: domain
    value: api.ip.sb
  - type: domain
    value: ident.me
  - type: domain
    value: www.myexternalip.com
  - type: domain
    value: zen.spamhaus.org
  - type: domain
    value: cbl.abuseat.org
  - type: domain
    value: b.barracudacentral.org
  - type: domain
    value: dnsbl-1.uceprotect.net
  - type: domain
    value: spam.dnsbl.sorbs.net
  - type: domain
    value: iplogger.org
  - type: domain
    value: ip-api.com
  - type: domain
    value: ipwho.is
  - type: domain
    value: ifconfig.me
  - type: domain
    value: myip.com
  - type: domain
    value: ipstack.com
  - type: domain
    value: myexternalip.com
  - type: domain
    value: ip-api.io
  - type: domain
    value: trackip.net
  - type: domain
    value: ipgeolocation.io
  - type: domain
    value: ipfind.io
  - type: domain
    value: freegeoip.app
  - type: domain
    value: ipv4bot.whatismyipaddress.com
ioc_counts:
  domain: 26
rules:
  - title: Detect Windows Process Querying Known IP Check Services via DNS
    description: Detects Windows processes making DNS queries to known IP check web services, often used for reconnaissance by malware.
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1590.005
    data_sources:
      - dns_query
      - windows
  - title: Detect Windows Process Querying Known IP Check Services via Sysmon EventID 22
    description: Detects Windows processes making DNS queries to known IP check web services logged via Sysmon EventID 22
    platform: sigma
    severity: medium
    tactics:
      - reconnaissance
    techniques:
      - T1590.005
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

This brief focuses on detecting malicious activity where Windows processes attempt to gather network information by querying publicly available IP check web services. This behavior is often observed during the reconnaissance phase of an attack, where malware or threat actors attempt to determine the external IP address of the compromised system. This information can then be used to tailor further attacks or for lateral movement within the network. The detection is based on identifying DNS queries to a list of known IP check services, as reported in Sysmon Event ID 22. This technique has been used by malware families such as Trickbot, Azorult, and others to profile infected systems. Defenders should monitor for these queries, especially from unusual processes or those not typically associated with network administration tasks.

## Attack Chain

1.  A user unknowingly executes a malicious executable (e.g., via phishing or drive-by download).
2.  The malicious executable initiates a process on the endpoint.
3.  The malicious process attempts to resolve a domain associated with a public IP check service (e.g., `wtfismyip.com`, `ipinfo.io`) using DNS.
4.  Sysmon Event ID 22 logs the DNS query, including the process name, queried domain, and query status.
5.  The malware receives the external IP address of the compromised system from the IP check service.
6.  The malware uses this IP address for further reconnaissance, such as identifying the victim's geographical location or organization.
7.  The attacker uses the gathered information to customize subsequent stages of the attack, such as delivering targeted payloads or exploiting vulnerabilities specific to the victim's network.
8.  The attacker may then attempt lateral movement, data exfiltration, or other malicious activities based on the network reconnaissance.

## Impact

A successful attack can lead to attackers gaining a comprehensive understanding of the victim's network environment, including their external IP address and geographical location. This information can be leveraged to refine attack strategies, deliver targeted payloads, and increase the likelihood of successful lateral movement and data exfiltration. Multiple malware families, including Trickbot and Azorult, utilize this technique.

## Recommendation

*   Enable Sysmon Event ID 22 logging with DNS query monitoring to capture the required events for the rules below.
*   Deploy the Sigma rules provided to detect processes querying known IP check web services in your environment and tune for legitimate use cases.
*   Review the IOCs listed to identify potential historical compromises and block DNS resolution to these domains.
*   Investigate any alerts generated by these rules, focusing on unusual process names or parent processes making these queries.
