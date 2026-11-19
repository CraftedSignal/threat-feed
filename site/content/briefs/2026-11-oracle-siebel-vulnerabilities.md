---
brief_id: brief-2026-11-18-oracle-siebel-vulnerabilities
event_id: brief-2026-11-18-oracle-siebel-vulnerabilities
revision: 2
activity_at: "2026-11-19T21:12:35Z"
revision_history:
  - revision: 2
    at: "2026-11-19T21:12:35Z"
    checksum: sha256:dcb5abf64f9711adc1a7f151d1d1999d22f899de6fd2b9da7129805e61bf8572
    summary: added CVE-2026-114976; siebel crm version 22.3-26.9
    changed_fields:
      - affected_products
      - cpes
      - cve_verification
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-114976
title: 'Oracle Siebel CRM: Multiple Vulnerabilities'
slug: 2026-11-oracle-siebel-vulnerabilities
description: The BSI has reported multiple vulnerabilities in Oracle Siebel CRM that allow remote, anonymous, or authenticated attackers to compromise system confidentiality, integrity, and availability.
date: "2026-11-18T09:18:15Z"
lastmod: "2026-11-19T21:10:28Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:oracle:siebel_crm:*:*:*:*:*:*:*:*
vendors:
  - Oracle
products:
  - Siebel CRM
product_versions:
  - product: Siebel CRM
    range: 22.3-26.9
cve_verification:
  CVE-2026-114976:
    status: verified
    source: cve_program
    checked_at: 2026-11-19T21:10:28.480169728Z
cves:
  - id: CVE-2026-114976
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4629
  - https://nvd.nist.gov/vuln/detail/CVE-2026-114976
action_plan:
  priority: elevated
  mitigation_plan:
    - priority: short_term
      action: Monitor official Oracle security advisories for patches addressing the reported vulnerabilities in Siebel CRM.
      addresses: Multiple vulnerabilities in Oracle Siebel CRM
      evidence: Source identifies multiple vulnerabilities without specific CVEs or versioning.
updates:
  - at: "2026-11-19T21:10:28Z"
    level: L2
    summary: added CVE-2026-114976; siebel crm version 22.3-26.9
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-114976
---

## Overview
The BSI has issued an advisory regarding multiple vulnerabilities in Oracle Siebel CRM. These vulnerabilities can be exploited by remote attackers, including anonymous or authenticated users.

## Impact
Successful exploitation may impact the confidentiality, integrity, and availability of the affected Oracle Siebel CRM deployment.

## Recommendation
Administrators should monitor official security channels from Oracle for specific updates and guidance regarding these vulnerabilities as provided in the referenced advisory.
