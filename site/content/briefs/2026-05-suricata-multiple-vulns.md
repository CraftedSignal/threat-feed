---
title: Multiple Vulnerabilities in Suricata Network Threat Detection Engine
slug: 2026-05-suricata-multiple-vulns
description: Multiple vulnerabilities in Suricata versions before 8.0.5 and 7.0.16 could allow a remote attacker to execute arbitrary code or cause a denial-of-service condition.
date: "2026-05-20T14:09:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - suricata
  - rce
  - dos
vendors:
  - Suricata
products:
  - Suricata
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Software Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0614/
  - https://suricata.io/2026/05/19/suricata-8-0-5-and-7-0-16-released/
  - https://www.cve.org/CVERecord?id=CVE-2026-45747
  - https://www.cve.org/CVERecord?id=CVE-2026-45751
  - https://www.cve.org/CVERecord?id=CVE-2026-45752
  - https://www.cve.org/CVERecord?id=CVE-2026-45759
  - https://www.cve.org/CVERecord?id=CVE-2026-45761
  - https://www.cve.org/CVERecord?id=CVE-2026-45762
  - https://www.cve.org/CVERecord?id=CVE-2026-45763
  - https://www.cve.org/CVERecord?id=CVE-2026-45764
  - https://www.cve.org/CVERecord?id=CVE-2026-45765
  - https://www.cve.org/CVERecord?id=CVE-2026-45766
  - https://www.cve.org/CVERecord?id=CVE-2026-45767
  - https://www.cve.org/CVERecord?id=CVE-2026-45768
  - https://www.cve.org/CVERecord?id=CVE-2026-45769
  - https://www.cve.org/CVERecord?id=CVE-2026-45770
  - https://www.cve.org/CVERecord?id=CVE-2026-46352
  - https://www.cve.org/CVERecord?id=CVE-2026-46387
rules:
  - title: Detect Suricata process crash
    description: Detects Suricata process crash based on process termination events.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Suricata config file change
    description: Detects Suricata configuration file changes
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1562.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

On May 20, 2026, the French CERT (CERT-FR) published an advisory regarding multiple vulnerabilities affecting Suricata, a network threat detection engine. The vulnerabilities impact Suricata versions prior to 8.0.5 and 7.0.16. Successful exploitation of these vulnerabilities could lead to remote code execution (RCE) and denial-of-service (DoS) conditions. The advisory identifies CVE-2026-45747, CVE-2026-45751, CVE-2026-45752, CVE-2026-45759, CVE-2026-45761, CVE-2026-45762, CVE-2026-45763, CVE-2026-45764, CVE-2026-45765, CVE-2026-45766, CVE-2026-45767, CVE-2026-45768, CVE-2026-45769, CVE-2026-45770, CVE-2026-46352, and CVE-2026-46387. Due to the nature of network threat detection engines, exploitation could severely impact network security monitoring capabilities.

## Attack Chain

Given the nature of Suricata as a network analysis tool, the attack chain depends on the specific vulnerability being exploited, but the general steps would involve:

1. An attacker crafts a malicious network packet or series of packets.
2. The attacker sends the malicious traffic to a network segment monitored by a vulnerable Suricata instance.
3. Suricata processes the malicious traffic.
4. A vulnerability in the Suricata parsing or processing logic is triggered by the crafted packet. This could involve a buffer overflow, integer overflow, or other memory corruption issue.
5. In the case of remote code execution, the attacker gains the ability to execute arbitrary code on the Suricata host.
6. The attacker could then use this access to pivot to other systems, exfiltrate sensitive information, or disrupt network monitoring.
7. In the case of a denial-of-service vulnerability, the Suricata process crashes or becomes unresponsive, preventing it from analyzing network traffic.

## Impact

Successful exploitation of these vulnerabilities can lead to a complete loss of network visibility if Suricata is used for intrusion detection or prevention. An attacker could potentially execute arbitrary code on the Suricata sensor, enabling lateral movement or data exfiltration. A successful denial-of-service attack could blind security teams to malicious activity on the network. The specific impact depends on the organization's reliance on Suricata for network security.

## Recommendation

*   Immediately upgrade Suricata to version 8.0.5 or 7.0.16 or later to patch the vulnerabilities described in the advisory.
*   Monitor network traffic for patterns associated with known Suricata exploits.
*   Implement network segmentation to limit the potential impact of a compromised Suricata instance.
*   Deploy the Sigma rules below to your SIEM to detect potential exploitation attempts of CVE-2026-45747, CVE-2026-45751, CVE-2026-45752, CVE-2026-45759, CVE-2026-45761, CVE-2026-45762, CVE-2026-45763, CVE-2026-45764, CVE-2026-45765, CVE-2026-45766, CVE-2026-45767, CVE-2026-45768, CVE-2026-45769, CVE-2026-45770, CVE-2026-46352, and CVE-2026-46387.
