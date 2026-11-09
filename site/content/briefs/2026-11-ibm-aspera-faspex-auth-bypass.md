---
brief_id: brief-2026-11-07-ibm-aspera-faspex-auth-bypass
event_id: brief-2026-11-07-ibm-aspera-faspex-auth-bypass
revision: 2
activity_at: "2026-11-09T22:12:33Z"
revision_history:
  - revision: 2
    at: "2026-11-09T22:12:33Z"
    checksum: sha256:31063ec13eb3129aeb4a0939c46dcbe2ac1ce24a4248fcd98e43a761d3453a96
    summary: exploited:true
    changed_fields:
      - affected_products
      - claim_state
      - cves
      - exploitation_evidence
      - lastmod
      - references
      - updates
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-123218
title: 'IBM Aspera Faspex: Authorization bypass and privilege escalation (CVE-2026-123218)'
slug: 2026-11-ibm-aspera-faspex-auth-bypass
description: IBM Aspera Faspex versions 5.0.0 through 5.0.19 could allow an authorized user to craft a specific message to bypass user authorization and gain full administrative privileges.
date: "2026-11-07T05:48:49Z"
lastmod: "2026-11-09T22:11:12Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - critical
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cve.org/CVERecord?id=CVE-2026-123218
  observed_at: "2026-11-09T00:00:00Z"
  confidence: high
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:ibm:aspera_faspex:*:*:*:*:*:*:*:*
vendors:
  - IBM
products:
  - Aspera Faspex (5.0.0 through 5.0.19)
  - Aspera Faspex
cves:
  - id: CVE-2026-123218
    cvss: 9.8
    epss: 0.00396
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-123218
  - https://www.cve.org/CVERecord?id=CVE-2026-123218
updates:
  - at: "2026-11-09T22:11:12Z"
    level: L3
    summary: exploited:true
    sources:
      - cisa-kev
    source_urls:
      - https://www.cve.org/CVERecord?id=CVE-2026-123218
---

IBM Aspera Faspex versions 5.0.0 through 5.0.19 are vulnerable to an authorization bypass. An authorized user can craft a specific message to gain full administrative privileges. The vulnerability has a CVSS v3.1 Base Score of 9.8.
