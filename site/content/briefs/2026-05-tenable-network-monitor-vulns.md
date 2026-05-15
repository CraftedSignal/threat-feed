---
title: Multiple Vulnerabilities in Tenable Network Monitor
slug: 2026-05-tenable-network-monitor-vulns
description: Multiple vulnerabilities in Tenable Network Monitor versions prior to 6.5.4 can lead to remote denial of service, security policy bypass, and unspecified security issues.
date: "2026-05-15T12:23:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*
  - cpe:2.3:a:sqlite:sqlite:*:*:*:*:*:*:*:*
  - cpe:2.3:a:sqlite:sqlite:3.49.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - dos
  - security-bypass
vendors:
  - Tenable
products:
  - Network Monitor (versions prior to 6.5.4)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1071
    technique_name: Application Layer Protocol
cves:
  - id: CVE-2025-15079
    cvss: 5.3
    epss: 0.00047
  - id: CVE-2025-15224
    cvss: 3.1
    epss: 0.00098
  - id: CVE-2025-29087
    cvss: 3.2
    epss: 0.00218
  - id: CVE-2025-29088
    cvss: 5.6
    epss: 0.00062
  - id: CVE-2025-3277
    cvss: 9.8
    epss: 0.00744
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0592/
  - https://www.tenable.com/security/tns-2026-14
  - https://www.cve.org/CVERecord?id=CVE-2025-13034
  - https://www.cve.org/CVERecord?id=CVE-2025-14017
  - https://www.cve.org/CVERecord?id=CVE-2025-14524
  - https://www.cve.org/CVERecord?id=CVE-2025-14819
  - https://www.cve.org/CVERecord?id=CVE-2025-15079
  - https://www.cve.org/CVERecord?id=CVE-2025-15224
  - https://www.cve.org/CVERecord?id=CVE-2025-29087
  - https://www.cve.org/CVERecord?id=CVE-2025-29088
  - https://www.cve.org/CVERecord?id=CVE-2025-3277
rules:
  - title: Detect Potential DoS against Tenable Network Monitor via Malformed Packets
    description: Detects unusual network traffic patterns indicative of DoS attacks against Tenable Network Monitor. This may detect exploitation attempts against CVE-2025-13034, CVE-2025-14017, CVE-2025-14524, CVE-2025-14819, CVE-2025-15079, CVE-2025-15224, CVE-2025-29087, CVE-2025-29088, CVE-2025-3277.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1499.001
    data_sources:
      - network_connection
      - windows
  - title: Detect Possible Policy Bypass Attempt on TNM
    description: Detects possible policy bypass attempt on TNM server. This may detect exploitation attempts against CVE-2025-13034, CVE-2025-14017, CVE-2025-14524, CVE-2025-14819, CVE-2025-15079, CVE-2025-15224, CVE-2025-29087, CVE-2025-29088, CVE-2025-3277.
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Tenable Network Monitor versions prior to 6.5.4 are susceptible to multiple vulnerabilities. According to Tenable's security advisory tns-2026-14, released on May 14, 2026, these vulnerabilities can allow an attacker to perform a remote denial of service (DoS), bypass security policies, and exploit unspecified security issues. The affected software is a network monitoring tool used within organizations to observe network traffic and identify potential security threats. Successful exploitation of these vulnerabilities could lead to network outages, unauthorized access, or other security breaches.

## Attack Chain

Due to lack of specific details about individual CVE exploitation, the following attack chain is generalized:

1.  Attacker identifies a vulnerable Tenable Network Monitor instance running a version prior to 6.5.4.
2.  Attacker crafts a malicious network packet or request targeting one of the vulnerabilities (CVE-2025-13034, CVE-2025-14017, CVE-2025-14524, CVE-2025-14819, CVE-2025-15079, CVE-2025-15224, CVE-2025-29087, CVE-2025-29088, CVE-2025-3277).
3.  The malicious packet is sent to the TNM server via network protocols (TCP/UDP).
4.  The TNM server processes the malformed packet, triggering the vulnerability.
5.  Depending on the specific vulnerability, this may cause a denial-of-service condition, preventing legitimate monitoring activity.
6.  Alternatively, it may bypass security policies, allowing unauthorized access to network data.
7.  The attacker may be able to execute arbitrary code on the TNM server, potentially gaining full control of the system (depending on the unspecified vulnerabilities).
8.  The attacker leverages compromised TNM to further compromise network.

## Impact

Successful exploitation of these vulnerabilities could lead to a denial of service, preventing administrators from monitoring network traffic and detecting threats. A security policy bypass could allow unauthorized access to sensitive network data. Unspecified vulnerabilities could lead to remote code execution, granting attackers complete control over the affected system. The number of potential victims is dependent on the install base of Tenable Network Monitor, but organizations relying on TNM for network security are at risk.

## Recommendation

*   Upgrade Tenable Network Monitor to version 6.5.4 or later to remediate the vulnerabilities (Tenable Security Advisory tns-2026-14).
*   Monitor network traffic for unusual patterns or large volumes of traffic directed towards Tenable Network Monitor servers (network_connection log source).
*   Deploy the provided Sigma rule to detect potential exploitation attempts targeting these vulnerabilities.
*   Review and harden network segmentation to limit the impact of a successful compromise.
