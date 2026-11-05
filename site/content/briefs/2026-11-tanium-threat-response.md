---
brief_id: brief-2026-11-04-tanium-threat-response
event_id: brief-2026-11-04-tanium-threat-response
revision: 1
activity_at: "2026-11-04T21:11:34Z"
title: 'Tanium Threat Response: Multiple security vulnerabilities'
slug: 2026-11-tanium-threat-response
description: Tanium has disclosed multiple vulnerabilities affecting several branches of the Threat Response module, requiring updates to patched versions 4.12.353, 4.17.333, and 4.9.480 or later.
date: "2026-11-04T21:11:34Z"
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
vendors:
  - Tanium
products:
  - Threat Response (< 4.12.353)
  - Threat Response (< 4.17.333)
  - Threat Response (< 4.9.480)
references:
  - https://cyber.gc.ca/en/alerts-advisories/tanium-security-advisory-av26-1120
  - https://security.tanium.com/TAN-2026-095
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Tanium Threat Response to 4.12.353, 4.17.333, or 4.9.480
      owner: IT Operations
      addresses: Vulnerabilities addressed in TAN-2026-095
      evidence: Source states updates are required for versions prior to these releases.
---

The Canadian Centre for Cyber Security has issued an advisory regarding vulnerabilities in the Tanium Threat Response module. Impacted versions include those prior to 4.12.353, 4.17.333, and 4.9.480. Details regarding the nature of these vulnerabilities remain undisclosed by the vendor; administrators should review TAN-2026-095 for specific remediation steps and security impact.

## Recommendation

* Inventory all instances of Tanium Threat Response within the environment.
* Upgrade Tanium Threat Response to version 4.12.353, 4.17.333, or 4.9.480, depending on the currently deployed branch, as directed by the vendor advisory TAN-2026-095.
* Monitor the Tanium Security Advisories portal for further technical details or updated remediation guidance.
