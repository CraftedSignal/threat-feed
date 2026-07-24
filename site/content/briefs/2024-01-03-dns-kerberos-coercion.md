---
title: DNS Kerberos Coercion Attempt Detection
slug: 2024-01-03-dns-kerberos-coercion
description: This brief details the detection of DNS-based Kerberos coercion attacks, where adversaries inject marshaled credential structures into DNS records to spoof SPNs and redirect authentication, as seen in CVE-2025-33073, using Suricata and Sysmon event ID 22.
date: "2024-01-03T12:00:00Z"
lastmod: "2026-07-24T07:06:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kerberos
  - coercion
  - dns
  - cve-2025-33073
vendors:
  - Fortinet
  - Cisco
  - Microsoft
  - F5
  - Atlassian
  - VMware
  - SAP
  - Ivanti
  - GitHub
  - Nx
  - Rocket.Chat
  - Erlang
  - TechPowerUp
  - RabbitMQ
  - Riak
  - CouchDB
products:
  - Fortinet edge appliances
  - Cisco edge appliances
  - OWA/M365
  - BIG-IP Virtual Edition (VE)
  - Confluence Data Center
  - Microsoft Defender XDR
  - Defender
  - BIG-IP
  - Confluence
  - Exchange Server
  - nx.dev
  - Metasploit
  - VMware Aria Operations
  - Fortinet FortiGate
  - Cisco
  - Microsoft software
  - Rocket.Chat
  - Fortinet firewalls
  - Fortinet VPN gateways
  - FortiCloud SSO Login
  - FortiGate
  - FortiCloud SSO
  - FortiOS
  - FortiCloud
  - FortiManager
  - FortiAnalyzer
  - FortiProxy
  - FortiSwitchManager
  - FortiWeb
  - Erlang/OTP SSH server
  - Windows SMB Client
  - ThrottleStop
  - ESXi
  - Erlang/OTP (<= 27.3.1)
  - Erlang/OTP (<= 26.2.5)
  - RabbitMQ Server
  - Riak
  - CouchDB
affected_os:
  - linux
  - Linux Kernel
  - Windows
  - ESXi
  - Logical Volume Manager
  - FortiOS
  - VMware ESXi
  - Windows 10 (< June 2025 patches)
  - Windows 11 (< June 2025 patches)
  - Windows Server (< June 2025 patches)
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1557
    technique_name: 'Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning'
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1187
    technique_name: Forced Authentication
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
references:
  - https://web.archive.org/web/20250617122747/https://www.synacktiv.com/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025
  - https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx
  - https://www.guidepointsecurity.com/blog/the-birth-and-death-of-loopyticket/
  - https://research.checkpoint.com/2026/thus-spoke-the-gentlemen/
  - https://www.microsoft.com/en-us/security/blog/2026/05/22/from-edge-appliance-to-enterprise-compromise-multi-stage-linux-intrusion-via-f5-and-confluence/
  - https://thehackernews.com/2026/05/ai-chatbot-recommendations-redirect.html
  - https://thehackernews.com/2026/06/the-gentlemen-ransomware-claims-478.html
  - https://cyber.gc.ca/en/alerts-advisories/al26-014-fortibleed-leak-thousands-compromised-credentials-impacting-fortinet-devices
  - https://www.securityweek.com/fortinet-responds-to-fortibleed-campaign/
  - https://blog.qualys.com/vulnerabilities-threat-research/2026/07/08/fortibleed-fortigate-credential-reuse-internet-exposed
  - https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/
  - https://sploitus.com/exploit?id=67F637FC-5651-557F-9948-A2BFAA8982D4&utm_source=rss&utm_medium=rss
  - https://sploitus.com/exploit?id=31A595C4-0B5A-5669-8E0C-5ED13794D9D1&utm_source=rss&utm_medium=rss
iocs:
  - type: domain
    value: gleeze[.]com
  - type: ip
    value: 176.120.22.127
  - type: url
    value: https://sploitus.com/exploit?id=31A595C4-0B5A-5669-8E0C-5ED13794D9D1
ioc_counts:
  domain: 1
  ip: 1
  url: 1
rules:
  - title: Detect DNS Queries with Kerberos Coercion Patterns (Suricata)
    description: Detects suspicious DNS queries containing specific patterns indicative of Kerberos coercion attacks, using Suricata logs.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1071.004
      - T1557.001
    data_sources:
      - network_connection
      - suricata
  - title: Detect DNS Queries with Kerberos Coercion Patterns (Sysmon Event ID 22)
    description: Detects suspicious DNS queries containing specific patterns indicative of Kerberos coercion attacks, using Sysmon Event ID 22 logs.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1071.004
      - T1557.001
    data_sources:
      - dns_query
      - windows
  - title: Detect Kerberos Coercion via DNS Queries by Suricata
    description: Detects Kerberos coercion attacks where adversaries inject marshaled credential structures into DNS records using Suricata.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1071.004
      - T1557.001
    data_sources:
      - network_connection
      - suricata
rules_count: 3
updates:
  - at: "2026-06-22T09:39:06Z"
    level: L1
    summary: new product
    sources:
      - securityweek
  - at: "2026-07-08T17:39:40Z"
    level: L2
    summary: added CVE-2025-59718 +2; OS fortios
    sources:
      - qualys-threat-research
    source_urls:
      - https://blog.qualys.com/vulnerabilities-threat-research/2026/07/08/fortibleed-fortigate-credential-reuse-internet-exposed
  - at: "2026-07-10T22:04:45Z"
    level: L2
    summary: added CVE-2025-32433 +1; OS vmware esxi
    sources:
      - unit42
    source_urls:
      - https://unit42.paloaltonetworks.com/the-gentlemen-ransomware/
  - at: "2026-07-13T13:02:08Z"
    level: L1
    summary: OS windows server (< june 2025 patches); OS windows 10 (< june 2025 patches); OS windows 11 (< june 2025 patches)
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=67F637FC-5651-557F-9948-A2BFAA8982D4&utm_source=rss&utm_medium=rss
  - at: "2026-07-24T07:06:14Z"
    level: L1
    summary: new IOCs
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=31A595C4-0B5A-5669-8E0C-5ED13794D9D1&utm_source=rss&utm_medium=rss
---

This brief addresses the threat of DNS-based Kerberos coercion attacks, which are designed to compromise authentication processes within a network. Attackers inject specifically crafted marshaled credential structures, identified by patterns like '*1UWhRC*', '*AAAAA*', and '*YBAAAA*', into DNS records. This injection allows the attacker to spoof Service Principal Names (SPNs) and redirect authentication requests, potentially leading to unauthorized access and lateral movement. The attack leverages vulnerabilities such as CVE-2025-33073. This activity has been observed leveraging both Suricata network monitoring and Windows Sysmon (Event ID 22) to detect the presence of these malicious DNS queries. Detection of this activity is critical to prevent Kerberos relay attacks and maintain the integrity of network authentication.

## Attack Chain

1.  The attacker gains initial access to a compromised host within the network.
2.  The attacker crafts a malicious DNS query containing marshaled `CREDENTIAL_TARGET_INFORMATION` structures.
3.  The compromised host sends the malicious DNS query to the internal DNS server.
4.  The DNS server processes the query, unknowingly forwarding the malicious data.
5.  The attacker intercepts the DNS response and uses the spoofed SPN to initiate a Kerberos authentication request.
6.  The target server authenticates to the attacker-controlled service, relaying credentials.
7.  The attacker leverages the relayed credentials to gain unauthorized access to network resources.
8.  The attacker escalates privileges and moves laterally within the network, achieving their final objective.

## Impact

A successful Kerberos coercion attack can lead to significant compromise of a network. By relaying credentials, attackers can gain unauthorized access to critical systems and data. While the exact number of potential victims is unknown, the impact can range from data breaches to complete network takeover. Sectors relying on Kerberos for authentication, such as government, finance, and healthcare, are particularly vulnerable. Successful exploitation allows attackers to escalate privileges, move laterally, and ultimately achieve their objectives, including data exfiltration or ransomware deployment.

## Recommendation

*   Ensure that DNS data is properly ingested and correlated with the Network Resolution data model in your SIEM to facilitate detection using the provided search query.
*   Implement the provided Sigma rules to detect suspicious DNS queries containing marshaled credential structures based on Suricata and Sysmon event ID 22 logs.
*   Investigate and patch CVE-2025-33073 on all affected systems to prevent exploitation of the vulnerability.
*   Review and tune the provided Sigma rules for false positives, filtering as needed for your organization's specific environment based on the known false positives.
*   Enable Sysmon Event ID 22 logging to enhance visibility into DNS query activity on Windows endpoints.
