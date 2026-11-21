---
brief_id: brief-2024-01-03-rdp-internet
event_id: brief-2024-01-03-rdp-internet
revision: 2
activity_at: "2026-11-21T16:46:26Z"
revision_history:
  - revision: 2
    at: "2026-11-21T16:46:26Z"
    checksum: sha256:0e1c925c6b30e2f11900cc54089565bc1ffd3a5cfc185faffddacfc53cadd192
    summary: exploited:true; KEV CVE-2019-0708
    changed_fields:
      - affected_products
      - affected_vendors
      - cves
      - exploitation_evidence
      - lastmod
      - priority_score
      - priority_signals
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: RDP (Remote Desktop Protocol) from the Internet
slug: 2024-01-rdp-internet
description: This rule detects network events indicative of RDP traffic originating from the internet, which poses a significant security risk due to its frequent exploitation as an initial access or backdoor vector.
date: "2024-01-03T14:30:00Z"
lastmod: "2026-11-21T16:45:43Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2021-11-03T00:00:00Z"
  confidence: high
tags:
  - command-and-control
  - lateral-movement
  - initial-access
  - rdp
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1021
    technique_name: Remote Services
    subtechnique_id: T1021.001
    subtechnique_name: Remote Desktop Protocol
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1133
    technique_name: External Remote Services
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2019-0708
    cvss: 9.8
    epss: 0.94454
    kev: true
    kev_status: "true"
references:
  - https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
  - https://attack.mitre.org/tactics/TA0011/
  - https://attack.mitre.org/tactics/TA0008/
  - https://attack.mitre.org/tactics/TA0001/
  - https://attack.mitre.org/techniques/T1021/
  - https://attack.mitre.org/techniques/T1021/001/
  - https://attack.mitre.org/techniques/T1133/
  - https://attack.mitre.org/techniques/T1190/
rules:
  - title: Detect RDP Connection from Internet to Internal Network
    description: Detects RDP connections originating from outside the internal network to internal IP ranges.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1021.001
    data_sources:
      - network_connection
      - windows
  - title: Detect RDP traffic via Zeek from Internet to Internal Network
    description: Detect RDP connections via Zeek logs originating from outside the internal network to internal IP ranges.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1021.001
    data_sources:
      - network_connection
      - zeek
rules_count: 2
updates:
  - at: "2026-11-21T16:45:43Z"
    level: L3
    summary: exploited:true; KEV CVE-2019-0708
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Remote Desktop Protocol (RDP) is a common tool for system administrators to remotely manage systems, however, exposing RDP directly to the internet creates a significant attack surface. Threat actors frequently target and exploit RDP for initial access, lateral movement, and establishing backdoors within compromised networks. This activity is detected by monitoring network traffic for RDP connections originating from outside the internal network (RFC1918 IP ranges). This is important because successful RDP compromise often leads to broader network infiltration and data exfiltration. This detection focuses on the network level characteristics of RDP connections from the internet to internal assets.

## Attack Chain

1. An attacker identifies a publicly accessible RDP service.
2. The attacker attempts to brute-force RDP login credentials or exploits a known RDP vulnerability (e.g. BlueKeep CVE-2019-0708).
3. Upon successful authentication or exploitation, the attacker gains remote access to the targeted system.
4. The attacker uses the compromised system as a pivot point to perform reconnaissance on the internal network.
5. The attacker moves laterally within the network using stolen credentials or by exploiting other vulnerabilities.
6. The attacker installs malware or establishes persistence mechanisms (e.g., creating new user accounts or modifying system configurations).
7. The attacker gathers sensitive data from internal systems.
8. The attacker exfiltrates the stolen data to an external server or deploys ransomware.

## Impact

Compromised RDP services can lead to significant data breaches, system downtime, and financial losses. Attackers can leverage RDP access to steal sensitive information, install ransomware, or disrupt critical business operations. While the number of affected organizations varies, RDP exploitation remains a prevalent attack vector, especially for organizations with inadequate security practices. The impact of a successful RDP attack ranges from several thousands to millions of dollars, depending on the size of the organization and the sensitivity of the compromised data.

## Recommendation

*   Deploy the "RDP (Remote Desktop Protocol) from the Internet" Sigma rule to your SIEM to detect unauthorized RDP connections from outside the network.
*   Review firewall rules and network configurations to ensure RDP services are not exposed directly to the internet. Implement a VPN or RDP gateway for secure remote access.
*   Enable and monitor network traffic logs (category: `network_traffic`, product: `windows|linux|macos`) to provide data for the Sigma rule.
*   Investigate any alerts generated by the Sigma rule, focusing on the source IP address and user accounts involved in the RDP connection.
*   Implement network segmentation to limit the blast radius of a potential RDP compromise.
