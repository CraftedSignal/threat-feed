---
title: Multiple Vulnerabilities Discovered in Wireshark Leading to DoS and Data Confidentiality Compromise
slug: 2026-07-wireshark-multivuln
description: Multiple vulnerabilities (CVE-2026-15163 through CVE-2026-15174) have been discovered in Wireshark, impacting versions 4.6.x prior to 4.6.7 and versions prior to 4.4.17, which could allow a remote attacker to cause a denial of service and compromise data confidentiality.
date: "2026-07-09T14:27:33Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - wireshark
  - dos
  - info-disclosure
  - product-vulnerability
vendors:
  - Wireshark
products:
  - Wireshark 4.6.x
  - Wireshark 4.4.x
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: permettent à un attaquant de provoquer un déni de service à distance
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Destruction
    evidence: une atteinte à la confidentialité des données
    confidence_band: high
cves:
  - id: CVE-2026-15163
    cvss: 5.5
  - id: CVE-2026-15166
    cvss: 5.5
  - id: CVE-2026-15170
    cvss: 5.5
  - id: CVE-2026-15172
    cvss: 5.5
  - id: CVE-2026-15173
    cvss: 4.7
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0849/
  - https://www.wireshark.org/security/wnpa-sec-2026-52.html
  - https://www.wireshark.org/security/wnpa-sec-2026-53.html
  - https://www.wireshark.org/security/wnpa-sec-2026-54.html
  - https://www.wireshark.org/security/wnpa-sec-2026-55.html
  - https://www.wireshark.org/security/wnpa-sec-2026-56.html
  - https://www.wireshark.org/security/wnpa-sec-2026-57.html
  - https://www.wireshark.org/security/wnpa-sec-2026-58.html
  - https://www.wireshark.org/security/wnpa-sec-2026-59.html
  - https://www.wireshark.org/security/wnpa-sec-2026-60.html
  - https://www.wireshark.org/security/wnpa-sec-2026-61.html
  - https://www.wireshark.org/security/wnpa-sec-2026-62.html
  - https://www.wireshark.org/security/wnpa-sec-2026-63.html
  - https://www.cve.org/CVERecord?id=CVE-2026-15163
  - https://www.cve.org/CVERecord?id=CVE-2026-15164
  - https://www.cve.org/CVERecord?id=CVE-2026-15165
  - https://www.cve.org/CVERecord?id=CVE-2026-15166
  - https://www.cve.org/CVERecord?id=CVE-2026-15167
  - https://www.cve.org/CVERecord?id=CVE-2026-15168
  - https://www.cve.org/CVERecord?id=CVE-2026-15169
  - https://www.cve.org/CVERecord?id=CVE-2026-15170
  - https://www.cve.org/CVERecord?id=CVE-2026-15171
  - https://www.cve.org/CVERecord?id=CVE-2026-15172
  - https://www.cve.org/CVERecord?id=CVE-2026-15173
  - https://www.cve.org/CVERecord?id=CVE-2026-15174
---

Multiple critical vulnerabilities, identified as CVE-2026-15163 through CVE-2026-15174, have been disclosed in Wireshark, a widely-used network protocol analyzer. These flaws affect Wireshark versions 4.6.x prior to 4.6.7 and all versions prior to 4.4.17. Published by CERT-FR on July 9, 2026, these vulnerabilities could enable a remote attacker to trigger a denial of service condition in the application, leading to instability or crashes. Furthermore, certain vulnerabilities could also facilitate an unauthorized compromise of data confidentiality, potentially exposing sensitive information being processed or analyzed by Wireshark. Organizations using vulnerable versions are strongly advised to patch immediately to mitigate the risk of disruption and data exposure posed by these publicly identified security issues.

## Attack Chain

1. **Attacker crafts malicious network traffic or capture file**: An attacker develops specifically malformed network packets or a corrupted capture file (e.g., PCAP, PCAPNG) targeting known vulnerabilities in Wireshark's dissection logic.
2. **Delivery of malicious input (network)**: The attacker transmits the crafted network traffic over a network segment monitored by a vulnerable Wireshark instance, relying on Wireshark to capture and process it.
3. **Delivery of malicious input (file)**: Alternatively, the attacker delivers the malicious capture file (e.g., via email, web download, or removable media) to a user of a vulnerable Wireshark installation.
4. **Wireshark processes malicious data**: The vulnerable Wireshark instance begins to dissect the malicious network traffic it captured or the user manually opens the malicious capture file.
5. **Vulnerability triggered in protocol dissector**: During the parsing of the malformed data, a flaw within one of Wireshark's protocol dissectors (e.g., memory corruption, infinite loop, buffer overflow) is triggered.
6. **Application crash (Denial of Service)**: The triggered vulnerability causes the Wireshark application to crash unexpectedly, resulting in a denial of service for the user.
7. **Potential information disclosure**: Depending on the specific vulnerability, an attacker might be able to read or leak sensitive data from the Wireshark process's memory space, leading to a confidentiality breach.

## Impact

The successful exploitation of these Wireshark vulnerabilities can lead to significant operational disruption for network analysts and security professionals. Remote attackers can cause the Wireshark application to crash, rendering it unusable and impacting ongoing network analysis tasks. Additionally, the data confidentiality breach aspect means that an attacker could potentially gain unauthorized access to sensitive network traffic data or other information residing in the memory of the Wireshark process. While no specific victim counts or targeted sectors are mentioned, any organization using vulnerable Wireshark versions for network monitoring, troubleshooting, or security analysis is at risk of operational downtime and sensitive data exposure.

## Recommendation

* Immediately patch CVE-2026-15163, CVE-2026-15164, CVE-2026-15165, CVE-2026-15166, CVE-2026-15167, CVE-2026-15168, CVE-2026-15169, CVE-2026-15170, CVE-2026-15171, CVE-2026-15172, CVE-2026-15173, and CVE-2026-15174 by updating all Wireshark installations to version 4.6.7 or later, or 4.4.17 or later, as specified in the affected products section.
