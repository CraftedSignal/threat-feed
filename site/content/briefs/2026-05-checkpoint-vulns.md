---
brief_id: brief-2026-05-checkpoint-vulns
event_id: brief-2026-05-checkpoint-vulns
revision: 2
activity_at: "2026-11-19T22:16:42Z"
revision_history:
  - revision: 2
    at: "2026-11-19T22:16:42Z"
    checksum: sha256:b0f0938dc7ecd91c38537e29db33534d9479f6015f518655102d349fcd8eec0d
    summary: exploited:true; KEV CVE-2026-0257
    changed_fields:
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - exploitation_evidence
      - lastmod
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Multiple Vulnerabilities in Check Point Products
slug: 2026-05-checkpoint-vulns
description: Multiple vulnerabilities in Check Point Security Gateways and Spark Firewalls allow for remote denial of service, data confidentiality breaches, and data integrity compromise.
date: "2026-05-27T14:32:27Z"
lastmod: "2026-11-19T22:16:04Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-05-29T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.10:-:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.10:h10:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.10:h12:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.10:h14:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.10:h17:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:-:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h12:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h16:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h18:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h19:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h1:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h21:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h24:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h32:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h3:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h6:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.7:h8:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.8:*:*:*:*:*:*:*
  - cpe:2.3:o:paloaltonetworks:pan-os:10.2.9:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - data-breach
  - sql-injection
vendors:
  - Carnival Corporation
  - Charter Communications
  - Check Point
  - Cloudflare
  - Facebook
  - Ghost
  - Gogs
  - Palo Alto Networks
  - Red Rock Resorts
  - ShinyHunters
products:
  - Ghost CMS
  - Gogs
  - PAN-OS GlobalProtect
  - Security Gateways R81.20
  - Security Gateways R82
  - Security Gateways R82.10
  - Spark Firewalls R81
  - Spark Firewalls R82
  - Spectrum
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1114
    technique_name: Email Collection
cves:
  - id: CVE-2026-48134
    cvss: 5.6
    epss: 0.00075
    kev_status: unknown
  - id: CVE-2026-48135
    cvss: 5.3
    epss: 0.00081
    kev_status: unknown
  - id: CVE-2026-48132
    cvss: 8.1
    epss: 0.00072
    kev_status: unknown
  - id: CVE-2026-0257
    cvss: 9.1
    epss: 0.41505
    kev: true
    kev_status: "true"
  - id: CVE-2026-48133
    cvss: 7.5
    epss: 0.00126
    kev_status: unknown
  - id: CVE-2026-48131
    kev_status: unknown
  - id: CVE-2026-48136
    kev_status: unknown
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0650/
  - https://support.checkpoint.com/results/sk/sk184981
  - https://support.checkpoint.com/results/sk/sk184982
  - https://support.checkpoint.com/results/sk/sk184983
  - https://support.checkpoint.com/results/sk/sk184991
  - https://support.checkpoint.com/results/sk/sk184992
  - https://support.checkpoint.com/results/sk/sk184993
  - https://www.cve.org/CVERecord?id=CVE-2026-48131
  - https://www.cve.org/CVERecord?id=CVE-2026-48132
  - https://www.cve.org/CVERecord?id=CVE-2026-48133
  - https://www.cve.org/CVERecord?id=CVE-2026-48134
  - https://www.cve.org/CVERecord?id=CVE-2026-48135
  - https://www.cve.org/CVERecord?id=CVE-2026-48136
  - https://research.checkpoint.com/2026/1st-june-threat-intelligence-report/
rules:
  - title: Detect CVE-2026-48131-48136 Exploitation Attempt - Suspicious URI
    description: Detects CVE-2026-48131-48136 exploitation attempts based on suspicious URI patterns indicative of SQL injection.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-48131-48136 Exploitation Attempt - Error Responses with Keywords
    description: Detects CVE-2026-48131-48136 exploitation attempts based on error responses containing SQL-related keywords.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-06-01T14:52:26Z"
    level: L2
    summary: added CVE-2026-0257 +2
    sources:
      - checkpoint
  - at: "2026-11-19T22:16:04Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-0257
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Multiple vulnerabilities have been identified in Check Point products, specifically Security Gateways and Spark Firewalls. These vulnerabilities can lead to significant security breaches, including remote denial-of-service (DoS) attacks, unauthorized access to sensitive data, and modification of data integrity. The affected products include Security Gateways versions R81.20 without hotfix 141, R82 without hotfix 103, and R82.10 without hotfix 19, as well as Spark Firewalls versions R81 prior to R81.10.17 and R82 prior to R82.00.10. Successful exploitation of these vulnerabilities could allow attackers to disrupt services, steal confidential information, or manipulate critical data.

## Attack Chain

1.  Attacker identifies a vulnerable Check Point Security Gateway or Spark Firewall running an unpatched version.
2.  The attacker crafts a malicious request to exploit one of the vulnerabilities (CVE-2026-48131 through CVE-2026-48136), such as an SQL injection.
3.  The malicious request is sent to the targeted device via network protocols (e.g., HTTP/HTTPS).
4.  The targeted device processes the request, triggering the vulnerability due to insufficient input validation or other security flaws.
5.  Depending on the specific vulnerability, the attacker achieves one or more of the following:
    *   Remote Denial of Service: The device becomes unresponsive or crashes, disrupting normal operations.
    *   Data Confidentiality Breach: Sensitive information is exposed to the attacker.
    *   Data Integrity Compromise: Data stored on or processed by the device is modified or corrupted.
6.  The attacker may leverage the initial compromise to gain further access to the network.
7.  The attacker may attempt to escalate privileges or move laterally within the network.
8.  The attacker exfiltrates sensitive data, disrupts operations, or causes further damage.

## Impact

Exploitation of these vulnerabilities can lead to severe consequences, including service disruption, data theft, and data corruption. Successful attacks could impact businesses of all sizes that rely on Check Point security solutions to protect their networks. The vulnerabilities affect Security Gateways and Spark Firewalls, potentially impacting network security, data confidentiality, and regulatory compliance.

## Recommendation

*   Apply the appropriate hotfixes as outlined in Check Point's security advisories (sk184981, sk184982, sk184983, sk184991, sk184992, sk184993) to patch the identified vulnerabilities in Security Gateways and Spark Firewalls.
*   Deploy the Sigma rules below to detect potential exploitation attempts targeting these vulnerabilities.
*   Monitor network traffic for suspicious activity that may indicate exploitation attempts, focusing on unusual requests to Check Point devices.
*   Review and enforce strict access control policies to limit the impact of potential data breaches.
