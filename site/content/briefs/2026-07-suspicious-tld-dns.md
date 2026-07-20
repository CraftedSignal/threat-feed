---
title: DNS Request to Suspicious Top Level Domain
slug: 2026-07-suspicious-tld-dns
description: This threat brief details how Linux systems making DNS queries to commonly abused top-level domains may indicate malware-related command and control (C2) communications, data exfiltration, or payload downloads, often blending into normal name resolution, signaling a potential compromise of servers, workstations, or containerized workloads.
date: "2026-07-20T13:14:03Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - command-and-control
  - exfiltration
  - linux
  - endpoint
  - network
  - detection
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: This rule detects DNS queries to commonly abused top level domains. Malware authors may use these domains to host command and control infrastructure, exfiltrate data, or to download payloads for later execution.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: This rule detects DNS queries to commonly abused top level domains that malware authors may use to host command and control infrastructure, which can involve external proxy usage.
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: Malware authors may use these domains to host command and control infrastructure, exfiltrate data, or to download payloads, often leveraging web services or dead drop resolvers.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: Malware authors may use these domains to host command and control infrastructure, facilitating bidirectional communication.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1568
    technique_name: Dynamic Resolution
    evidence: This rule flags a Linux process making DNS lookups for top-level domains that threat actors frequently abuse, which can reveal command-and-control staging, payload retrieval, or data theft paths that blend into normal name resolution. A common pattern is a compromised Linux server or container resolving a .xyz, .top, or .ru domain immediately before a downloader, backdoor, or script beacon starts exchanging instructions or uploading collected data.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Malware authors may use these domains to host command and control infrastructure, exfiltrate data, or to download payloads for later execution.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Malware authors may use these domains to host command and control infrastructure, exfiltrate data, or to download payloads for later execution.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Malware authors may use these domains to host command and control infrastructure, exfiltrate data, or to download payloads for later execution.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/command_and_control_dns_query_to_sus_top_level_domain.toml
iocs:
  - type: domain
    value: '*.forum'
  - type: domain
    value: '*.pro'
  - type: domain
    value: '*.team'
  - type: domain
    value: '*.lol'
  - type: domain
    value: '*.kr'
  - type: domain
    value: '*.ke'
  - type: domain
    value: '*.nu'
  - type: domain
    value: '*.space'
  - type: domain
    value: '*.capital'
  - type: domain
    value: '*.in'
  - type: domain
    value: '*.cfd'
  - type: domain
    value: '*.online'
  - type: domain
    value: '*.ru'
  - type: domain
    value: '*.info'
  - type: domain
    value: '*.top'
  - type: domain
    value: '*.buzz'
  - type: domain
    value: '*.xyz'
  - type: domain
    value: '*.rest'
  - type: domain
    value: '*.ml'
  - type: domain
    value: '*.cf'
  - type: domain
    value: '*.gq'
  - type: domain
    value: '*.ga'
  - type: domain
    value: '*.onion'
  - type: domain
    value: '*.network'
  - type: domain
    value: '*.monster'
  - type: domain
    value: '*.marketing'
  - type: domain
    value: '*.cyou'
  - type: domain
    value: '*.quest'
  - type: domain
    value: '*.cc'
  - type: domain
    value: '*.bar'
  - type: domain
    value: '*.click'
  - type: domain
    value: '*.cam'
  - type: domain
    value: '*.surf'
  - type: domain
    value: '*.tk'
  - type: domain
    value: '*.shop'
  - type: domain
    value: '*.club'
  - type: domain
    value: '*.icu'
  - type: domain
    value: '*.pw'
  - type: domain
    value: '*.ws'
  - type: domain
    value: '*.fun'
  - type: domain
    value: '*.life'
  - type: domain
    value: '*.boats'
  - type: domain
    value: '*.store'
  - type: domain
    value: '*.hair'
  - type: domain
    value: '*.mom'
  - type: domain
    value: '*.beauty'
  - type: domain
    value: '*.bond'
  - type: domain
    value: '*.biz'
  - type: domain
    value: '*.live'
  - type: domain
    value: '*.zone'
ioc_counts:
  domain: 50
rules:
  - title: DNS Request to Suspicious Top Level Domain
    description: Detects DNS queries originating from Linux systems to commonly abused top-level domains that malware authors frequently use for command and control (C2), data exfiltration, or payload delivery.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1071.004
      - T1567
    data_sources:
      - dns_query
      - linux
rules_count: 1
---

This brief focuses on the detection of suspicious DNS queries originating from Linux systems to Top Level Domains (TLDs) frequently exploited by malicious actors. These TLDs, such as `.xyz`, `.top`, `.ru`, and numerous others including `.onion`, are chosen by malware authors to host command and control (C2) infrastructure, facilitate data exfiltration, or serve as distribution points for additional malicious payloads. The presence of such DNS lookups can be a critical indicator of compromise on a Linux server, workstation, or containerized workload, revealing hidden malicious network activity that may otherwise blend into legitimate name resolution traffic. The pattern often observed is a compromised Linux host resolving one of these TLDs just before a downloader, backdoor, or script beacon initiates communication, exchanges instructions, or attempts to upload collected data. This activity, while not an initial access vector, is a strong signal of post-exploitation activity, highlighting the need for vigilance against such network behaviors.

## Attack Chain

1. An attacker gains initial access to a Linux system through various means, such as exploiting a vulnerability, phishing, or compromised credentials.
2. Malware is deployed and executed on the compromised Linux host, establishing a foothold within the environment.
3. The malicious process initiates a DNS lookup to resolve a command and control (C2) server or data exfiltration endpoint.
4. The DNS query targets a domain residing under a suspicious or commonly abused Top Level Domain (TLD), such as `malicious.xyz` or `beacon.ru`, attempting to blend with legitimate network traffic.
5. The DNS request is resolved, providing the malware with the IP address of its C2 infrastructure or data drop point.
6. The malware establishes an outbound connection to the resolved malicious IP address for data exfiltration, payload download, or receiving further commands.
7. Data is exfiltrated from the compromised system, or additional malware components are downloaded and executed, furthering the attacker's objectives.
8. The attacker maintains persistence and control over the compromised Linux system, continuing C2 communications through domains within suspicious TLDs.

## Impact

The successful execution of an attack leveraging suspicious TLDs for C2 or data exfiltration can lead to significant impact, including unauthorized access to sensitive data, installation of further malicious software like ransomware, and establishment of persistent access for future exploitation. Compromised Linux servers or workstations could become part of a botnet, serve as launchpads for lateral movement, or be used to disrupt critical services. While this brief does not detail specific victim counts or sectors, the use of such TLDs is prevalent across various cybercrime and advanced persistent threat (APT) campaigns targeting any organization operating Linux environments. The primary damage is data breach, system compromise, and potential financial and reputational losses due to attacker control and malicious actions.

## Recommendation

* Deploy the provided Sigma rule to your SIEM and tune for your environment to detect DNS queries to commonly abused TLDs on Linux systems.
* Ensure DNS logging is enabled on all Linux endpoints and network devices to capture `dns.question.name` data, which is crucial for the rule to function.
* Enrich the queried domain and any resolved IPs with passive DNS, registration age, reputation, ASN, or geolocation information to distinguish newly created or low-reputation infrastructure from known business services, as suggested in the "Investigating DNS Request to Suspicious Top Level Domain" guide.
* Block the suspicious Top Level Domains (TLDs) listed in the IOC table at your network's DNS resolver and firewall controls to prevent connections to known malicious infrastructure.
* Isolate any Linux host or container flagged by the "DNS Request to Suspicious Top Level Domain" rule from the network, except for approved management access, and immediately block associated suspicious domains and IP addresses.
