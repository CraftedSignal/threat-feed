---
brief_id: brief-2026-07-cisco-security-updates
event_id: brief-2026-07-cisco-security-updates
revision: 2
activity_at: "2026-11-19T18:13:06Z"
revision_history:
  - revision: 2
    at: "2026-11-19T18:13:06Z"
    checksum: sha256:d75fb98a43b7d8594f538b74a9ba3731899522c7c4c0ea60094f4aea4231aecb
    summary: exploited:true; KEV CVE-2026-20079; KEV CVE-2026-20316
    changed_fields:
      - affected_os
      - affected_products
      - affected_vendors
      - cpes
      - cves
      - exploitation_evidence
      - iocs
      - lastmod
      - priority
      - priority_score
      - priority_signals
      - references
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: Cisco Security Updates — July 2026
slug: 2026-07-cisco-security-updates
description: Roundup of Cisco security advisories published in July 2026.
date: "2026-07-03T13:36:20Z"
lastmod: "2026-11-19T18:12:21Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-07-29T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:*:*:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.3.0:-:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.3.0:patch10:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.3.0:patch11:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.3.0:patch1:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.3.0:patch2:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.3.0:patch3:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.3.0:patch4:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.3.0:patch5:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.3.0:patch6:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.3.0:patch7:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.3.0:patch8:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.3.0:patch9:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.4.0:-:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.4.0:patch1:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.4.0:patch2:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.4.0:patch3:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.4.0:patch4:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.4.0:patch5:*:*:*:*:*:*
  - cpe:2.3:a:cisco:identity_services_engine_passive_identity_connector:3.4.0:patch6:*:*:*:*:*:*
  - cpe:2.3:a:cisco:secure_firewall_management_center:*:*:*:*:*:*:*:*
tags:
  - roundup
vendors:
  - Cisco
cves:
  - id: CVE-2026-20146
    cvss: 5.5
    epss: 0.0034
    kev_status: unknown
  - id: CVE-2026-20150
    cvss: 8.8
    epss: 0.00222
    kev_status: unknown
  - id: CVE-2026-20079
    cvss: 10
    epss: 0.387
    kev: true
    kev_status: "true"
  - id: CVE-2026-20187
    cvss: 7.5
    epss: 0.00252
    kev_status: unknown
  - id: CVE-2026-20316
    cvss: 5.3
    kev: true
    kev_status: "true"
  - id: CVE-2026-20156
    kev_status: unknown
  - id: CVE-2026-20157
    kev_status: unknown
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-traversal-xNt7wb2Y?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Identity%20Services%20Engine%20Path%20Traversal%20Vulnerability%26vs_k=1
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20150
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20156
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20157
  - https://nvd.nist.gov/vuln/detail/CVE-2026-20187
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-onprem-fmc-authbypass-5JPp45V2?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Authentication%20Bypass%20%20Vulnerability%26vs_k=1
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-static-cred-BET3Cjh?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Static%20Credential%20Vulnerability%26vs_k=1
updates:
  - at: "2026-07-29T15:57:45Z"
    level: L2
    summary: added CVE-2026-20079
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-onprem-fmc-authbypass-5JPp45V2?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Authentication%20Bypass%20%20Vulnerability%26vs_k=1
  - at: "2026-07-29T16:01:19Z"
    level: L2
    summary: added CVE-2026-20187
    sources:
      - cisco-psirt
    source_urls:
      - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fmc-static-cred-BET3Cjh?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Secure%20Firewall%20Management%20Center%20Software%20Static%20Credential%20Vulnerability%26vs_k=1
  - at: "2026-07-29T18:58:28Z"
    level: L2
    summary: secure firewall management center version FMC
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-20316
  - at: "2026-07-30T07:16:28Z"
    level: L2
    summary: poc_available; added CVE-2026-20316
    sources:
      - the-hacker-news
    source_urls:
      - https://thehackernews.com/2026/07/cisco-fmc-zero-day-actively-exploited.html
  - at: "2026-11-19T18:12:21Z"
    level: L3
    summary: exploited:true; KEV CVE-2026-20079; KEV CVE-2026-20316
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Aggregated Cisco security advisories for July 2026. CVEs from this cycle are folded
into the list below as they are published.

## Recommendation

Review affected products and apply Cisco's July 2026 security updates.
