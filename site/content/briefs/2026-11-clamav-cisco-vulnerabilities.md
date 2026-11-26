---
brief_id: brief-2026-11-23-clamav-cisco-vulnerabilities
event_id: brief-2026-11-23-clamav-cisco-vulnerabilities
revision: 2
activity_at: "2026-11-26T11:15:01Z"
revision_history:
  - revision: 2
    at: "2026-11-26T11:15:01Z"
    checksum: sha256:4d43d8bce26d234c76da76471d712b75656af66edc29383ef3d55bf60c73e660
    summary: added CVE-2026-76411
    changed_fields:
      - cve_verification
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76411
title: 'ClamAV and Cisco Secure Endpoint Connector: Multiple vulnerabilities'
slug: 2026-11-clamav-cisco-vulnerabilities
description: Multiple vulnerabilities in ClamAV and the Cisco Secure Endpoint Connector allow remote anonymous attackers to bypass security measures, manipulate data, and induce a denial-of-service state.
date: "2026-11-23T10:42:28Z"
lastmod: "2026-11-26T11:14:41Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "3"
  rating: A3
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Waiting for vendor specific version details
vendors:
  - Cisco
products:
  - ClamAV
  - Secure Endpoint Connector
cve_verification:
  CVE-2026-76411:
    status: verified
    source: nvd
    checked_at: 2026-11-26T11:14:41.194770471Z
cves:
  - id: CVE-2026-76411
    cvss: 7.5
    epss: 0.00603
    kev_status: "false"
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4662
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76411
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory environment for ClamAV and Cisco Secure Endpoint Connector deployments
      owner: IT Operations
      due: 48h
      evidence: Advisory identifies ClamAV and Cisco Secure Endpoint Connector as vulnerable products
  enrichment_needed:
    - item: CVE identifiers and patched version numbers
      owner: CTI
      reason: Vulnerability details are currently undisclosed in the primary source
      evidence: BSI advisory currently lacks specific technical identifiers
  gaps:
    - Missing specific version identifiers and technical exploit path details
updates:
  - at: "2026-11-26T11:14:41Z"
    level: L2
    summary: added CVE-2026-76411
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-76411
---

## Overview

The BSI has reported multiple vulnerabilities affecting ClamAV and the Cisco Secure Endpoint Connector. These flaws allow a remote, anonymous attacker to bypass existing security controls, perform data manipulation, and cause a denial-of-service condition within the affected software. Specific CVE identifiers and technical details for these vulnerabilities are currently undisclosed in the primary advisory. Administrators are advised to monitor the vendor security portals for upcoming patches and remediation steps.

## Impact

Successful exploitation could result in the compromise of security control integrity, unauthorized data manipulation, and system instability leading to a denial-of-service (DoS) state.

## Recommendation

1. Inventory all instances of ClamAV and Cisco Secure Endpoint Connector within the environment.
2. Monitor vendor security advisories from Cisco for specific version releases and patch guidance to remediate these vulnerabilities.
3. Implement network segmentation and access controls to limit remote exposure of instances running affected software until security updates are applied.
