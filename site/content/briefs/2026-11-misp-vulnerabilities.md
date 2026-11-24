---
brief_id: brief-2026-11-24-misp-vulnerabilities
event_id: brief-2026-11-24-misp-vulnerabilities
revision: 2
activity_at: "2026-11-24T18:31:34Z"
revision_history:
  - revision: 2
    at: "2026-11-24T18:31:34Z"
    checksum: sha256:d4e668816806337467249a9275967c049841ca934517235bc7faea3e5fc54c0c
    summary: poc_available; added CVE-2026-135239; misp version < 2.5.52
    changed_fields:
      - affected_products
      - cpes
      - cve_verification
      - cves
      - has_poc
      - lastmod
      - poc_references
      - references
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=85CFA9C4-FCD3-5A05-9C5A-349AA987B0B7&utm_source=rss&utm_medium=rss
title: 'MISP: Multiple Vulnerabilities'
slug: 2026-11-misp-vulnerabilities
description: Multiple vulnerabilities in the Malware Information Sharing Platform (MISP) could allow remote attackers to perform denial of service, information disclosure, unauthorized file manipulation, cross-site scripting (XSS), and security control bypass.
date: "2026-11-24T17:03:03Z"
lastmod: "2026-11-24T18:30:11Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
qa_status:
  verdict: pass_with_fixes
  validation_status: Waiting for official vendor patch release to define remediation versions.
cpes:
  - cpe:2.3:a:misp_project:misp:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=85CFA9C4-FCD3-5A05-9C5A-349AA987B0B7&utm_source=rss&utm_medium=rss
vendors:
  - MISP Project
products:
  - MISP
product_versions:
  - product: MISP
    range: < 2.5.52
cve_verification:
  CVE-2026-135239:
    status: verified
    source: nvd
    checked_at: 2026-11-24T18:30:10.997759944Z
cves:
  - id: CVE-2026-135239
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4751
  - https://sploitus.com/exploit?id=85CFA9C4-FCD3-5A05-9C5A-349AA987B0B7&utm_source=rss&utm_medium=rss
action_plan:
  priority: enrich_before_decision
  owners:
    - SOC
    - CTI
  immediate_actions:
    - action: Subscribe to official MISP project security release notifications and monitor their GitHub repository for updates.
      owner: CTI
      due: 24h
      evidence: Source advisory indicates multiple vulnerabilities exist without providing fixed version strings.
  enrichment_needed:
    - item: Vulnerability details, including CVEs and affected versions
      owner: CTI
      reason: The BSI advisory provides high-level categories of impact but lacks the technical specifics required to identify vulnerable instances or apply patches.
      evidence: Source WID-SEC-2026-4751
  hunt_leads:
    - lead: Monitor web access logs for unusual patterns targeting common MISP endpoints or anomalous query parameters indicative of XSS or path manipulation attempts.
      data_needed:
        - Web server access logs (Apache/Nginx)
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source notes potential for XSS and file manipulation via vulnerabilities.
  gaps:
    - Lack of specific indicators or version information in the initial advisory.
updates:
  - at: "2026-11-24T18:30:11Z"
    level: L2
    summary: poc_available; added CVE-2026-135239; misp version < 2.5.52
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=85CFA9C4-FCD3-5A05-9C5A-349AA987B0B7&utm_source=rss&utm_medium=rss
---

## Overview

Multiple security vulnerabilities have been identified in the MISP (Malware Information Sharing Platform) software. According to the BSI security advisory, these flaws allow an unauthenticated or authenticated attacker to perform various malicious actions, including triggering denial of service conditions, accessing sensitive information, manipulating files, executing cross-site scripting (XSS) attacks, and bypassing existing security controls. The advisory does not currently detail the specific underlying mechanisms or CVE identifiers for these vulnerabilities.

## Impact

Successful exploitation could lead to a loss of availability (Denial of Service), compromise of sensitive intelligence data (Information Disclosure), loss of system integrity (File Manipulation), execution of malicious scripts in user browsers (XSS), and full or partial bypass of security mechanisms depending on the specific vulnerability targeted.
