---
brief_id: brief-2024-01-03-dns-kerberos-coercion
event_id: brief-2024-01-03-dns-kerberos-coercion
revision: 2
activity_at: "2026-11-20T03:11:01Z"
revision_history:
  - revision: 2
    at: "2026-11-20T03:11:01Z"
    checksum: sha256:8189ea02476eeb9e7f62400a0f388da1612646a39573bf1c4ede997fb911f985
    summary: exploited:true; KEV CVE-2025-33073; KEV CVE-2025-32433; KEV CVE-2025-59718
    changed_fields:
      - cpes
      - cves
      - exploitation_evidence
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: DNS Kerberos Coercion Attempt Detection
slug: 2024-01-03-dns-kerberos-coercion
description: This brief details the detection of DNS-based Kerberos coercion attacks, where adversaries inject marshaled credential structures into DNS records to spoof SPNs and redirect authentication, as seen in CVE-2025-33073, using Suricata and Sysmon event ID 22.
date: "2024-01-03T12:00:00Z"
lastmod: "2026-11-20T03:10:25Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2025-06-09T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:cisco:cloud_native_broadband_network_gateway:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:confd_basic:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:enterprise_nfv_infrastructure_software:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:inode_manager:-:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:network_services_orchestrator:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:optical_site_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:smart_phy:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:ultra_cloud_core:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:ultra_packet_core:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:ultra_services_platform:-:*:*:*:*:*:*:*
  - cpe:2.3:a:erlang:erlang\/otp:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*
  - cpe:2.3:a:fortinet:fortiswitchmanager:*:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:ncs_2000_shelf_virtualization_orchestrator_firmware:*:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:rv160_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:rv160w_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:rv260_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:rv260p_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:rv260w_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:rv340_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:rv340w_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:cisco:staros:*:*:*:*:*:*:*:*
  - cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1507:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1607:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_10_1809:*:*:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_10_21h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_10_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2008:-:sp2:*:*:*:*:x86:*
  - cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:x64:*
  - cpe:2.3:o:microsoft:windows_server_2012:-:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2012:r2:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2016:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2019:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*
  - cpe:2.3:o:microsoft:windows_server_2022_23h2:*:*:*:*:*:*:*:*
  - cpe:2.3:o:siemens:ruggedcom_ape1808_firmware:-:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=6D5BC7E6-C0A6-54A0-8116-47799C31DFA2&utm_source=rss&utm_medium=rss
tags:
  - kerberos
  - coercion
  - dns
  - cve-2025-33073
vendors:
  - Atlassian
  - Cisco
  - CouchDB
  - Erlang
  - F5
  - Fortinet
  - GitHub
  - Ivanti
  - Microsoft
  - Nx
  - RabbitMQ
  - Riak
  - Rocket.Chat
  - SAP
  - TechPowerUp
  - VMware
products:
  - BIG-IP
  - BIG-IP Virtual Edition (VE)
  - Cisco
  - Cisco edge appliances
  - Confluence
  - Confluence Data Center
  - CouchDB
  - Defender
  - Erlang/OTP
  - Erlang/OTP SSH server
  - ESXi
  - Exchange Server
  - FortiAnalyzer
  - FortiCloud
  - FortiCloud SSO
  - FortiCloud SSO Login
  - FortiGate
  - FortiManager
  - Fortinet edge appliances
  - Fortinet firewalls
  - Fortinet FortiGate
  - Fortinet VPN gateways
  - FortiOS
  - FortiProxy
  - FortiSwitchManager
  - FortiWeb
  - Metasploit
  - Microsoft Defender XDR
  - Microsoft software
  - nx.dev
  - OWA/M365
  - RabbitMQ Server
  - Riak
  - Rocket.Chat
  - ThrottleStop
  - ThrottleStop.sys
  - VMware Aria Operations
  - Windows SMB Client
product_versions:
  - product: Erlang/OTP
    range: <= 26.2.5
  - product: Erlang/OTP
    range: <= 27.3.1
  - product: ThrottleStop.sys
    range: 3.0.0.0
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
    technique_name: Adversary-in-the-Middle
    subtechnique_id: T1557.001
    subtechnique_name: LLMNR/NBT-NS Poisoning and SMB Relay
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1187
    technique_name: Forced Authentication
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    subtechnique_id: T1071.004
    subtechnique_name: DNS
cves:
  - id: CVE-2025-33073
    cvss: 8.8
    epss: 0.78515
    kev: true
    kev_status: "true"
  - id: CVE-2025-7771
    epss: 0.06835
    kev_status: unknown
  - id: CVE-2025-32433
    cvss: 10
    epss: 0.98594
    kev: true
    kev_status: "true"
  - id: CVE-2025-59718
    cvss: 9.8
    epss: 0.63443
    kev: true
    kev_status: "true"
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
  - https://sploitus.com/exploit?id=6D5BC7E6-C0A6-54A0-8116-47799C31DFA2&utm_source=rss&utm_medium=rss
iocs:
  - type: domain
    value: gleeze[.]com
  - type: ip
    value: 176.120.22.127
  - type: url
    value: https://sploitus.com/exploit?id=31A595C4-0B5A-5669-8E0C-5ED13794D9D1
  - type: hash_sha256
    value: 16F83F056177C4EC24C7E99D01CA9D9D6713BD0497EEEDB777A3FFEFA99C97F0
ioc_counts:
  domain: 1
  hash_sha256: 1
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
  - at: "2026-08-11T00:45:00Z"
    level: L2
    summary: poc_available; added CVE-2025-32433 +3
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=6D5BC7E6-C0A6-54A0-8116-47799C31DFA2&utm_source=rss&utm_medium=rss
  - at: "2026-11-20T03:10:25Z"
    level: L3
    summary: exploited:true; KEV CVE-2025-33073; KEV CVE-2025-32433; KEV CVE-2025-59718
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

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
