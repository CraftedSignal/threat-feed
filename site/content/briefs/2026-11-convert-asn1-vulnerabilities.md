---
brief_id: brief-2026-11-20-convert-asn1-vulnerabilities
event_id: brief-2026-11-20-convert-asn1-vulnerabilities
revision: 1
activity_at: "2026-11-20T03:46:54Z"
title: 'Convert::ASN1: CPU exhaustion via bigint loop (CVE-2026-126540)'
slug: 2026-11-convert-asn1-vulnerabilities
description: Convert::ASN1 versions prior to 0.37 allow for remote CPU exhaustion through a quadratic time complexity flaw in the os2ip function when processing oversized INTEGER or ENUMERATED types.
date: "2026-11-20T03:46:54Z"
lastmod: "2026-11-20T21:11:32Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Vulnerability details verified against CVE Program source; no additional environment validation required.
products:
  - Convert-ASN1
  - Convert::ASN1
product_versions:
  - product: Convert-ASN1
    range: < 0.37
  - product: Convert::ASN1
    range: < 0.37
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An attacker who controls the decoded data can exhaust CPU with a single oversized INTEGER or ENUMERATED value.
    confidence_band: high
cves:
  - id: CVE-2026-126540
    kev_status: "false"
  - id: CVE-2026-126568
    kev_status: "false"
  - id: CVE-2026-126576
    kev_status: "false"
  - id: CVE-2026-126682
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/797
  - https://cveawg.mitre.org/api/cve/CVE-2026-126540
  - https://cveawg.mitre.org/api/cve/CVE-2026-126568
  - https://cveawg.mitre.org/api/cve/CVE-2026-126576
  - https://cveawg.mitre.org/api/cve/CVE-2026-126682
  - https://nvd.nist.gov/vuln/detail/CVE-2026-126540
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Software Engineering
  immediate_actions:
    - action: Inventory applications and services using Convert::ASN1 for Perl.
      owner: Software Engineering
      due: 48h
      evidence: Vulnerabilities present in versions < 0.37.
  hunt_leads:
    - lead: Identify Perl application processes experiencing sustained, anomalous CPU spikes correlated with heavy network input or file processing involving ASN.1 encoded data structures.
      technique_id: T1499
      data_needed:
        - Process CPU usage metrics
        - Application execution logs
        - Process module/library load lists
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Convert::ASN1 versions before 0.37 for Perl allow CPU exhaustion via quadratic bigint loop in os2ip, where decoding an n-octet INTEGER or ENUMERATED value takes O(n^2) bigint work.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Convert-ASN1 0.37 or later.
      owner: IT Operations
      addresses: CVE-2026-126540, CVE-2026-126568, CVE-2026-126576, CVE-2026-126682
      evidence: Primary CVE evidence states upgrade to 0.37 or later as the solution.
    - priority: immediate
      action: Upgrade Convert-ASN1 to version 0.37 or later.
      evidence: Upgrade to Convert-ASN1 0.37 or later.
  gaps:
    - No specific Sigma rule available for this algorithmic complexity attack.
updates:
  - at: "2026-11-20T21:11:32Z"
    level: L1
    summary: added coverage for Convert-ASN1 (< 0.37)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-126540
---

## Overview
Convert::ASN1 versions prior to 0.37 are vulnerable to a denial-of-service attack. The issue exists within the os2ip function, which processes ASN.1 INTEGER or ENUMERATED types exceeding four octets. The function iterates over each content octet using a bigint multiplication process that grows by one octet per step. Because there is no validation of content length, an attacker controlling the decoded data can provide an oversized value to trigger O(n^2) bigint work, resulting in CPU exhaustion.

## Impact
Successful exploitation allows an attacker to exhaust CPU resources, leading to a denial-of-service condition for applications using the affected library to process untrusted ASN.1 data.

## Recommendation
Upgrade the Convert-ASN1 package to version 0.37 or later. Users should audit applications for usage of this library to process externally-supplied ASN.1 data and implement input length validation as a defense-in-depth measure.
