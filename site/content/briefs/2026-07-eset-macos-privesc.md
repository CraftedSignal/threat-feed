---
title: Multiple Privilege Escalation Vulnerabilities in ESET macOS Products
slug: 2026-07-eset-macos-privesc
description: Multiple vulnerabilities discovered in ESET Cyber Security and Endpoint Security for macOS allow an attacker to achieve privilege escalation on affected systems, posing a significant risk to macOS users.
date: "2026-07-24T13:24:29Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - macos
vendors:
  - ESET
products:
  - Cyber Security for macOS (prior to 9.0.6300.0)
  - Endpoint Security for macOS 9.0.x (prior to 9.0.6400.0)
  - Endpoint Security for macOS 9.1.x (prior to 9.1.3100.0)
  - Endpoint Security for macOS (prior to 8.1.300.0)
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: De multiples vulnérabilités ont été découvertes dans les produits ESET. Elles permettent à un attaquant de provoquer une élévation de privilèges.
    confidence_band: high
cves:
  - id: CVE-2026-10610
  - id: CVE-2026-7483
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0932/
  - https://support-feed.eset.com/link/15370/17386418/ca8974
  - https://support-feed.eset.com/link/15370/17386417/ca8977
  - https://www.cve.org/CVERecord?id=CVE-2026-10610
  - https://www.cve.org/CVERecord?id=CVE-2026-7483
iocs:
  - type: url
    value: https://support-feed.eset.com/link/15370/17386418/ca8974
  - type: url
    value: https://support-feed.eset.com/link/15370/17386417/ca8977
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-10610
  - type: url
    value: https://www.cve.org/CVERecord?id=CVE-2026-7483
ioc_counts:
  url: 4
---

CERT-FR has issued an advisory regarding multiple privilege escalation vulnerabilities affecting ESET Cyber Security and Endpoint Security products on macOS. These vulnerabilities, identified as CVE-2026-10610 and CVE-2026-7483, could allow a local attacker to elevate their privileges on an affected system. The vulnerabilities impact various versions of ESET's macOS security solutions, specifically Cyber Security for macOS versions prior to 9.0.6300.0, Endpoint Security for macOS 9.0.x prior to 9.0.6400.0, Endpoint Security for macOS 9.1.x prior to 9.1.3100.0, and Endpoint Security for macOS prior to 8.1.300.0. While the specific exploitation details are not public, the nature of privilege escalation vulnerabilities means that an attacker who has already gained initial access to a system could leverage these flaws to gain higher-level control, bypassing security controls provided by ESET.

## Impact

A successful exploitation of these vulnerabilities would result in an attacker achieving elevated privileges, potentially gaining root or administrative access on the compromised macOS system. This level of access allows an attacker to perform a wide range of malicious activities, including installing persistent malware, modifying critical system configurations, exfiltrating sensitive data, or completely disabling security software. While no specific victim numbers or targeted sectors are mentioned, any organization or individual utilizing the affected ESET products on macOS is at risk. The primary impact is the bypass of intended security boundaries and the potential for complete system compromise.

## Recommendation

* Refer to ESET's security bulletins for patches, specifically bulletins `ca8974` and `ca8977`, and apply the updates immediately to address `CVE-2026-10610` and `CVE-2026-7483`.
* Ensure ESET Cyber Security for macOS is updated to version 9.0.6300.0 or later.
* Ensure ESET Endpoint Security for macOS 9.0.x is updated to version 9.0.6400.0 or later.
* Ensure ESET Endpoint Security for macOS 9.1.x is updated to version 9.1.3100.0 or later.
* Ensure ESET Endpoint Security for macOS is updated to version 8.1.300.0 or later.
