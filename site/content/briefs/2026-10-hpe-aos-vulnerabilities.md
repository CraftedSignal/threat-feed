---
brief_id: brief-2026-10-23-hpe-aos-vulnerabilities
event_id: brief-2026-10-23-hpe-aos-vulnerabilities
revision: 2
activity_at: "2026-10-23T15:41:17Z"
revision_history:
  - revision: 2
    at: "2026-10-23T15:41:17Z"
    checksum: sha256:0f32cec8eba1cd0a27f8231398e20aa9aa0324ee0969559276e4ef14bba78643
    summary: added CVE-2026-79844 +3
    changed_fields:
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://pwn.watch/i/hpe-aruba-aos-critical-rce-oct-2026
title: HPE Networking Wireless Operating System Multiple Vulnerabilities
slug: 2026-10-hpe-aos-vulnerabilities
description: HPE has addressed multiple vulnerabilities affecting various versions of its Networking Wireless Operating Systems (AOS-10 and AOS-8) that require firmware updates.
date: "2026-10-23T15:00:46Z"
lastmod: "2026-10-23T15:40:37Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:hpe:networking_wireless_operating_systems:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - networking
  - patch-management
  - informational
vendors:
  - HPE
products:
  - HPE Networking Wireless Operating Systems (AOS-10 < 10.8.1.2, 10.7.2.7, 10.4.1.14; AOS-8 < 8.13.3.1, 8.10.0.24)
cves:
  - id: CVE-2026-79844
    cvss: 10
    epss: 0.004
    kev_status: "false"
  - id: CVE-2026-79845
    cvss: 7.3
    epss: 0.00431
    kev_status: "false"
  - id: CVE-2026-79846
    cvss: 10
    epss: 0.00499
    kev_status: "false"
  - id: CVE-2026-79851
    cvss: 10
    epss: 0.00499
    kev_status: "false"
references:
  - https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw05162en_us&docLocale=en_US
  - https://support.hpe.com/connect/s/securitybulletinlibrary?language=en_US
  - https://cyber.gc.ca/en/alerts-advisories/hpe-security-advisory-av26-1079
  - https://pwn.watch/i/hpe-aruba-aos-critical-rce-oct-2026
  - https://csaf.arubanetworking.hpe.com/2026/hpe_networking_-_hpesbnw05162.txt
  - https://www.cve.org/CVERecord?id=CVE-2026-79844
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  mitigation_plan:
    - priority: immediate
      action: Upgrade HPE Networking Wireless Operating Systems to versions 10.8.1.2, 10.7.2.7, 10.4.1.14, 8.13.3.1, 8.10.0.24 or later.
      owner: IT Operations
      addresses: HPE Networking Wireless Operating System vulnerabilities
      evidence: HPE security advisory HPESBNW05162
updates:
  - at: "2026-10-23T15:40:37Z"
    level: L2
    summary: added CVE-2026-79844 +3
    sources:
      - pwn-watch
    source_urls:
      - https://pwn.watch/i/hpe-aruba-aos-critical-rce-oct-2026
---

HPE has released a security advisory (HPESBNW05162) addressing multiple vulnerabilities affecting HPE Networking Wireless Operating Systems, specifically AOS-10 and AOS-8 releases. The vulnerabilities affect versions prior to 10.8.1.2, 10.7.2.7, 10.4.1.14, 8.13.3.1, and 8.10.0.24. Administrators should consult the linked security bulletin for specific remediation paths and patch availability.

## Recommendation

- Identify all instances of HPE Networking Wireless Operating Systems (AOS-10 and AOS-8) within the network environment.
- Upgrade firmware to the following versions or later: 10.8.1.2, 10.7.2.7, 10.4.1.14, 8.13.3.1, or 8.10.0.24.
- Monitor the HPE Security Bulletin Library for any additional disclosures or updates related to these advisory revisions.
