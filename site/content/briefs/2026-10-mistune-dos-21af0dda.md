---
brief_id: brief-2026-10-22-mistune-dos-21af0dda
event_id: brief-2026-10-22-mistune-dos-21af0dda
revision: 1
activity_at: "2026-10-22T20:27:56Z"
title: 'Mistune: Algorithmic complexity denial of service (CVE-2026-115348)'
slug: 2026-10-mistune-dos-21af0dda
description: Mistune versions 3.0.0 through 3.2.x are vulnerable to an algorithmic complexity issue in the parse_link_text function, allowing unauthenticated attackers to trigger CPU exhaustion via crafted Markdown containing unbalanced brackets.
date: "2026-10-22T20:27:56Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against CVE-2026-115348 advisory data.
cpes:
  - cpe:2.3:a:lepture:mistune:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - vulnerability
  - markdown-parser
vendors:
  - lepture
products:
  - Mistune (3.0.0 - 3.2.x)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can submit Markdown containing many unbalanced '[' or '![' characters, forcing repeated unbounded forward scans and tying up worker processes for minutes.
    confidence_band: high
cves:
  - id: CVE-2026-115348
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115348
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Inventory all applications utilizing Mistune versions 3.0.0 through 3.2.x
      owner: Application Security
      due: 48h
      evidence: Source identifies vulnerability in Mistune 3.0.0 through 3.2.x
  mitigation_plan:
    - priority: immediate
      action: Upgrade Mistune to version 3.3.0 or later
      owner: IT Operations
      addresses: CVE-2026-115348
      evidence: NVD advisory indicates vulnerability is present in versions before 3.3.0
---

Mistune versions 3.0.0 through 3.2.x contain an algorithmic complexity vulnerability in the `parse_link_text` function. The vulnerability arises from how the inline link parser handles unbalanced brackets, allowing attackers to supply crafted Markdown input with excessive '[' or '![' characters. This causes the parser to perform repeated unbounded forward scans, which can lead to CPU exhaustion and the denial of service of worker processes.

## Impact

Successful exploitation can lead to a denial of service (DoS) by consuming CPU resources, potentially causing application-level performance degradation or service outages by exhausting available worker processes.

## Recommendation

Update the Mistune library to version 3.3.0 or later to include the fix for CVE-2026-115348. Applications that accept user-provided Markdown input and process it using affected versions of Mistune should prioritize this patch.
