---
brief_id: brief-2026-10-22-mistune-dos-b11c7be4
event_id: brief-2026-10-22-mistune-dos-b11c7be4
revision: 1
activity_at: "2026-10-22T20:28:10Z"
title: 'Mistune: Algorithmic complexity denial of service (CVE-2026-115352)'
slug: 2026-10-mistune-dos-b11c7be4
description: Mistune versions prior to 3.3.0 are susceptible to an algorithmic complexity vulnerability in the inline link parser, allowing unauthenticated attackers to cause CPU exhaustion via crafted markdown payloads.
date: "2026-10-22T20:28:10Z"
lastmod: "2026-10-22T20:28:23Z"
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
  - cpe:2.3:a:mistune_project:mistune:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - algorithmic-complexity
  - markdown-parser
vendors:
  - Mistune
products:
  - Mistune (< 3.3.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can send small markdown payloads that trigger O(N^2) parse_link_text and parse_link_label probing, occupying rendering workers for 30+ seconds per 16 KB input.
    confidence_band: high
cves:
  - id: CVE-2026-115352
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-115355
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115352
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115355
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Mistune to version 3.3.0 or later
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-115352 advisory
  mitigation_plan:
    - priority: immediate
      action: Limit input size for markdown parsing routines to reduce CPU exhaustion window
      owner: Detection Engineering
      addresses: CVE-2026-115352
      evidence: Source notes that processing 16KB of input causes 30+ seconds of CPU occupation
updates:
  - at: "2026-10-22T20:28:23Z"
    level: L2
    summary: added coverage for Mistune (< 3.3.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-115355
---

Mistune before 3.3.0 contains an algorithmic complexity vulnerability in the inline link parser. An unauthenticated attacker can exploit this by submitting specifically crafted markdown payloads containing long sequences of unmatched '[' characters. This triggers O(N^2) complexity in the 'parse_link_text' and 'parse_link_label' functions, leading to significant CPU exhaustion and denial of service of rendering workers, with observed impacts of 30+ seconds per 16 KB of input.

## Impact
Successful exploitation results in high CPU utilization on servers rendering user-supplied markdown, potentially leading to service degradation or denial of service for the application relying on the Mistune parser.

## Recommendation
- Upgrade Mistune to version 3.3.0 or later to include the fix for the algorithmic complexity flaw.
- Implement request size limits on inputs processed by Mistune to mitigate the impact of O(N^2) complexity payloads if immediate patching is not feasible.
- Audit applications utilizing Mistune for public-facing markdown rendering to identify high-risk exposure points.
