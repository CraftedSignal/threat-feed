---
title: Multiple Vulnerabilities in Squid Proxy (CVE-2026-47729, CVE-2026-50012)
slug: 2026-06-squid-vulnerabilities
description: Multiple vulnerabilities, including CVE-2026-47729 and CVE-2026-50012, have been identified in Squid proxy versions prior to 7.6, allowing an attacker to compromise data confidentiality and cause other unspecified security issues.
date: "2026-06-23T11:55:10Z"
lastmod: "2026-07-18T07:05:31Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - squid
  - proxy
  - data-confidentiality
  - network-device
vendors:
  - Squid
products:
  - Squid (< 7.6)
  - Squid (FTP gateway)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: De multiples vulnérabilités ont été découvertes dans Squid. Elles permettent à un attaquant de provoquer une atteinte à la confidentialité des données
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Local System
    evidence: Elles permettent à un attaquant de provoquer une atteinte à la confidentialité des données
    confidence_band: med
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over C2 Channel
    evidence: atteinte à la confidentialité des données
    confidence_band: med
cves:
  - id: CVE-2026-47729
    cvss: 6.5
    epss: 0.01907
  - id: CVE-2026-50012
    cvss: 5.5
    epss: 0.02252
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0795/
  - https://github.com/squid-cache/squid/security/advisories/GHSA-5vmx-9x64-9284
  - https://github.com/squid-cache/squid/security/advisories/GHSA-8c37-pxjq-qwrg
  - https://www.cve.org/CVERecord?id=CVE-2026-47729
  - https://www.cve.org/CVERecord?id=CVE-2026-50012
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47729
updates:
  - at: "2026-07-18T07:05:31Z"
    level: L2
    summary: added CVE-2026-47729 +1
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-47729
---

On June 23, 2026, the French National Agency for the Security of Information Systems (ANSSI) CERT-FR issued an advisory highlighting multiple vulnerabilities, identified as CVE-2026-47729 and CVE-2026-50012, in Squid proxy software. These vulnerabilities affect all Squid versions prior to 7.6. An unspecified attacker could exploit these flaws to achieve data confidentiality impairment and other undefined security problems. The presence of these vulnerabilities poses a significant risk to organizations using vulnerable Squid instances, as they could lead to unauthorized access to sensitive information flowing through the proxy or stored on the server. Defenders must prioritize patching to mitigate potential exploitation and safeguard network traffic integrity.

## Attack Chain

1.  An attacker identifies a publicly accessible Squid proxy server running a vulnerable version (prior to 7.6).
2.  The attacker crafts and sends a specially malformed HTTP request or a series of requests to the vulnerable Squid server, targeting either CVE-2026-47729 or CVE-2026-50012.
3.  The Squid proxy's vulnerable component processes the malicious request without proper validation or sanitization.
4.  Successful exploitation of the vulnerability grants the attacker unauthorized access to internal data or network traffic handled by the proxy.
5.  This access leads to the impairment of data confidentiality, allowing the attacker to read or capture sensitive information.
6.  The attacker leverages the compromised access to potentially exfiltrate sensitive data from the targeted network.
7.  Exploitation may also trigger other unspecified security issues within the Squid proxy environment, potentially leading to further compromise.

## Impact

The identified vulnerabilities in Squid versions prior to 7.6 can lead to a significant compromise of data confidentiality. While the source does not specify victim counts or targeted sectors, any organization utilizing Squid as a proxy, especially for sensitive data transmission, is at risk. Successful exploitation could result in unauthorized access to internal network communications, user credentials, and other proprietary information. The "unspecified security problem" further indicates potential for broader adverse effects beyond just data leakage, such as service disruption or further network penetration. The absence of specific exploit details prevents a precise enumeration of consequences, but the general risk to data confidentiality is high.

## Recommendation

*   Immediately update all Squid proxy installations to version 7.6 or later, as recommended in the Squid security bulletins linked in this brief.
*   Ensure network segmentation and firewall rules are in place to restrict access to Squid proxy instances to only necessary sources, limiting the attack surface for CVE-2026-47729 and CVE-2026-50012.
*   Deploy the latest security patches for CVE-2026-47729 and CVE-2026-50012 by following the vendor's documentation at the provided GitHub advisory URLs.
