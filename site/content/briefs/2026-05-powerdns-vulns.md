---
title: PowerDNS Authoritative Server Multiple Vulnerabilities
slug: 2026-05-powerdns-vulns
description: Multiple vulnerabilities in PowerDNS Authoritative Server allow an attacker to disclose information, manipulate data, and cause a denial-of-service condition.
date: "2026-05-22T06:54:34Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
  - information-disclosure
vendors:
  - PowerDNS
products:
  - Authoritative Server
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Information Discovery
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1625
rules:
  - title: PowerDNS Authoritative Server - Suspicious Query Patterns
    description: Detects suspicious DNS query patterns that may indicate exploitation attempts against PowerDNS Authoritative Server.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - dns_query
      - windows
  - title: PowerDNS Authoritative Server - High Error Rate
    description: Detects a high rate of DNS server errors, which may indicate a denial-of-service attack against PowerDNS Authoritative Server.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1498
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

Multiple vulnerabilities exist within PowerDNS Authoritative Server. An attacker could exploit these weaknesses to achieve several malicious outcomes. These include unauthorized disclosure of sensitive information, the ability to manipulate existing data, and the potential to initiate a denial-of-service (DoS) condition, rendering the server unavailable to legitimate users. This vulnerability advisory highlights the potential risks associated with running unpatched instances of PowerDNS Authoritative Server and underscores the need for timely security updates. The advisory serves as a critical alert for system administrators responsible for maintaining PowerDNS Authoritative Server instances.

## Attack Chain

1.  Attacker identifies a vulnerable PowerDNS Authoritative Server instance.
2.  Attacker crafts a malicious request targeting a specific vulnerability, such as a buffer overflow or input validation issue.
3.  The malicious request is sent to the PowerDNS Authoritative Server.
4.  The server processes the request, triggering the vulnerability.
5.  Depending on the vulnerability, the attacker may be able to disclose sensitive information, such as zone data or internal configurations.
6.  Alternatively, the attacker could manipulate data stored on the server, potentially altering DNS records.
7.  The attacker may also be able to cause a denial-of-service condition by crashing the server or exhausting its resources.

## Impact

Successful exploitation of these vulnerabilities can lead to significant consequences. Information disclosure could expose sensitive zone data, allowing attackers to gain insights into the target network's infrastructure. Data manipulation could allow attackers to redirect traffic to malicious servers by altering DNS records. A denial-of-service condition would prevent legitimate users from resolving domain names, disrupting network services and potentially causing financial losses.

## Recommendation

*   Upgrade PowerDNS Authoritative Server to the latest patched version as provided by the vendor to remediate the vulnerabilities described.
*   Monitor network traffic for suspicious requests targeting PowerDNS Authoritative Server to detect potential exploitation attempts. Deploy the Sigma rules below to your SIEM to identify malicious activity.
