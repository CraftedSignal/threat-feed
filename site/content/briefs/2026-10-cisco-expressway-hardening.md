---
brief_id: brief-2026-10-21-cisco-expressway-hardening
event_id: brief-2026-10-21-cisco-expressway-hardening
revision: 1
activity_at: "2026-10-21T17:08:11Z"
title: Cisco Expressway Series security hardening update
slug: 2026-10-cisco-expressway-hardening
description: Cisco has released a software hardening update to address eight vulnerabilities (CVE-2026-76490 through CVE-2026-76497) identified during an internal security review of the Expressway Core and Edge series.
date: "2026-10-21T17:08:11Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: unlikely
qa_status:
  verdict: pass
  validation_status: Verified against Cisco PSIRT advisory
tags:
  - patch-management
  - security-hardening
  - product-news
vendors:
  - Cisco
products:
  - Expressway Core
  - Expressway Edge
cves:
  - id: CVE-2026-76490
    kev_status: unknown
  - id: CVE-2026-76491
    kev_status: unknown
  - id: CVE-2026-76492
    kev_status: unknown
  - id: CVE-2026-76493
    kev_status: unknown
  - id: CVE-2026-76494
    kev_status: unknown
  - id: CVE-2026-76495
    kev_status: unknown
  - id: CVE-2026-76496
    kev_status: unknown
  - id: CVE-2026-76497
    kev_status: unknown
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-exwy-hardening-FhcqBVcs
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-notice-QGwHnJ6k
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-exwy-hardening-FhcqBVcs?vs_f=Cisco%20Security%20Advisory%26vs_cat=Security%20Intelligence%26vs_type=RSS%26vs_p=Cisco%20Expressway%20Series%20Security%20Hardening%20Release:%20October%202026%26vs_k=1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all Cisco Expressway Core and Edge devices to the current hardened software release
      owner: IT Operations
      due: 72h
      evidence: Cisco advises that no workarounds exist and a software update is required to address the vulnerabilities
  mitigation_plan:
    - priority: immediate
      action: Apply provided software hardening update
      owner: IT Operations
      addresses: CVE-2026-76490, CVE-2026-76491, CVE-2026-76492, CVE-2026-76493, CVE-2026-76494, CVE-2026-76495, CVE-2026-76496, CVE-2026-76497
      evidence: Source advisory confirms patch availability for the named CVEs
---

Cisco has released a security hardening update for the Cisco Expressway Series, including both Expressway Core and Expressway Edge devices. This update addresses eight vulnerabilities discovered during an internal security review. Cisco notes that these vulnerabilities were discovered internally, are not known to be actively exploited, and have no available workarounds. Cisco has grouped these vulnerabilities by their underlying Common Weakness Enumeration (CWE) class, assigning each group a unique CVE identifier. Further details regarding individual vulnerabilities may be provided in subsequent separate security advisories.

## Impact

Cisco has assigned a High severity rating to the vulnerabilities addressed in this release. There is no evidence of active exploitation at this time.

## Recommendation

- Inventory all Cisco Expressway Core and Expressway Edge deployments to ensure visibility.
- Apply the latest software hardening update provided by Cisco to all affected instances immediately, as no workarounds are available.
- Monitor the Cisco Security Intelligence website for future granular advisories regarding these specific CVEs (CVE-2026-76490, CVE-2026-76491, CVE-2026-76492, CVE-2026-76493, CVE-2026-76494, CVE-2026-76495, CVE-2026-76496, CVE-2026-76497).
