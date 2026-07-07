---
title: Detection of DNS Queries to Suspicious Top-Level Domains
slug: 2026-07-suspicious-tld-dns
description: This rule detects DNS queries originating from Linux systems that target commonly abused top-level domains, which adversaries frequently leverage to establish command and control (C2) communications, exfiltrate sensitive data, or stage and deliver malicious payloads, indicating potential compromise or ongoing malicious activity.
date: "2026-07-06T17:29:03Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - command-and-control
  - exfiltration
  - linux
  - dns
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Malware authors may use these domains to host command and control infrastructure
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1090
    technique_name: Proxy
    evidence: Malware authors may use these domains to host command and control infrastructure
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: Malware authors may use these domains to host command and control infrastructure
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
    evidence: Malware authors may use these domains to host command and control infrastructure
    confidence_band: med
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1568
    technique_name: Dynamic Resolution
    evidence: Malware authors may use these domains to host command and control infrastructure
    confidence_band: med
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Malware authors may use these domains to ... exfiltrate data
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Malware authors may use these domains to ... exfiltrate data
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Malware authors may use these domains to ... exfiltrate data
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/command_and_control_dns_query_to_sus_top_level_domain.toml
iocs:
  - type: domain
    value: .forum
  - type: domain
    value: .pro
  - type: domain
    value: .team
  - type: domain
    value: .lol
  - type: domain
    value: .kr
  - type: domain
    value: .ke
  - type: domain
    value: .nu
  - type: domain
    value: .space
  - type: domain
    value: .capital
  - type: domain
    value: .in
  - type: domain
    value: .cfd
  - type: domain
    value: .online
  - type: domain
    value: .ru
  - type: domain
    value: .info
  - type: domain
    value: .top
  - type: domain
    value: .buzz
  - type: domain
    value: .xyz
  - type: domain
    value: .rest
  - type: domain
    value: .ml
  - type: domain
    value: .cf
  - type: domain
    value: .gq
  - type: domain
    value: .ga
  - type: domain
    value: .onion
  - type: domain
    value: .network
  - type: domain
    value: .monster
  - type: domain
    value: .marketing
  - type: domain
    value: .cyou
  - type: domain
    value: .quest
  - type: domain
    value: .cc
  - type: domain
    value: .bar
  - type: domain
    value: .click
  - type: domain
    value: .cam
  - type: domain
    value: .surf
  - type: domain
    value: .tk
  - type: domain
    value: .shop
  - type: domain
    value: .club
  - type: domain
    value: .icu
  - type: domain
    value: .pw
  - type: domain
    value: .ws
  - type: domain
    value: .fun
  - type: domain
    value: .life
  - type: domain
    value: .boats
  - type: domain
    value: .store
  - type: domain
    value: .hair
  - type: domain
    value: .mom
  - type: domain
    value: .beauty
  - type: domain
    value: .bond
  - type: domain
    value: .biz
  - type: domain
    value: .live
  - type: domain
    value: .zone
ioc_counts:
  domain: 50
rules:
  - title: DNS Request to Suspicious Top Level Domain
    description: Detects DNS queries from Linux systems to commonly abused top-level domains used by malware for C2, exfiltration, or payload delivery.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - exfiltration
    techniques:
      - T1071
      - T1071.004
      - T1090
      - T1090.002
      - T1102
      - T1102.001
      - T1102.002
      - T1567
      - T1567.001
      - T1567.002
      - T1567.003
      - T1568
      - T1568.002
    data_sources:
      - dns_query
      - linux
rules_count: 1
---

This brief details a detection rule from Elastic designed to identify suspicious DNS queries originating from Linux systems. The rule targets a broad list of top-level domains (TLDs) that are frequently abused by threat actors for various malicious purposes. These TLDs, such as .ru, .xyz, .top, .info, and many others, are common choices for hosting command and control (C2) infrastructure, facilitating data exfiltration, or serving as staging grounds for downloading additional malware payloads. The goal of this detection is to provide early warning of potential compromises or ongoing malicious activities by flagging communications with infrastructure known for its illicit use. Defenders can deploy this rule to monitor network traffic for anomalous outbound connections from Linux endpoints, thereby enhancing their ability to detect and respond to covert attacker communications.

## Attack Chain

(No specific attack chain is documented in the source. This detection focuses on identifying post-compromise network behaviors rather than initial access or specific exploitation.)

## Impact

Failure to detect and block DNS queries to suspicious TLDs can lead to significant consequences for an organization. If a compromised Linux system successfully establishes command and control (C2) with attacker infrastructure, it enables persistent access, further exploitation, data exfiltration, or the deployment of ransomware. The impact can range from data breaches and intellectual property theft to complete network disruption and financial losses. Early detection of such communication attempts is crucial to prevent the progression of an attack and mitigate potential damage, which could otherwise affect any system within the network communicating with these domains.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune it for your Linux environment, prioritizing critical servers and workstations.
*   Ensure DNS logging is enabled for all Linux endpoints, capturing `dns.question.name`, `host.os.type`, and `process.name` to activate the rule effectively.
*   Consider implementing network egress filtering to restrict outbound DNS queries to only known, legitimate TLDs or internal DNS resolvers.
*   Investigate all alerts generated by the "DNS Request to Suspicious Top Level Domain" rule by examining the source process and the full domain name for context.
