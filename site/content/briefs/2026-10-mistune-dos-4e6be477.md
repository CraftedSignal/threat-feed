---
brief_id: brief-2026-10-22-mistune-dos-4e6be477
event_id: brief-2026-10-22-mistune-dos-4e6be477
revision: 1
activity_at: "2026-10-22T22:30:42Z"
title: 'Mistune: Algorithmic complexity denial of service in parse_link_text (CVE-2026-115349)'
slug: 2026-10-mistune-dos-4e6be477
description: Mistune versions 3.0.0 through 3.2.x are vulnerable to a denial-of-service attack where crafted Markdown inputs with nested square brackets cause excessive CPU consumption during parsing.
date: "2026-10-22T22:30:42Z"
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
  validation_status: Patch released in 3.3.0; verify versioning in environment
cpes:
  - cpe:2.3:a:mistune_project:mistune:*:*:*:*:*:*:*:*
products:
  - Mistune (3.0.0 - 3.2.x)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can submit markdown with deeply nested square brackets triggering quadratic parsing time, exhausting server CPU with small crafted requests.
    confidence_band: high
cves:
  - id: CVE-2026-115349
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115349
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade Mistune to version 3.3.0 or later
      owner: IT Operations
      due: 72h
      evidence: Source notes vulnerability fixed in 3.3.0
  mitigation_plan:
    - priority: immediate
      action: Upgrade affected libraries to 3.3.0
      owner: IT Operations
      addresses: CVE-2026-115349
      evidence: NVD source confirms 3.3.0 release
---

Mistune versions 3.0.0 before 3.3.0 contain an algorithmic complexity vulnerability in the `parse_link_text` function within `src/mistune/helpers.py`. The vulnerability allows a remote attacker to cause a denial-of-service condition by submitting small, specially crafted Markdown strings containing deeply nested square brackets. This input triggers a quadratic complexity in the parsing logic, leading to high CPU usage and service exhaustion.

## Impact

Successful exploitation results in service degradation or complete denial of service for applications utilizing the affected version of Mistune to process user-supplied Markdown input, as CPU resources are monopolized by the inefficient regex processing.

## Recommendation

* Upgrade the `mistune` library to version 3.3.0 or later immediately.
* Identify applications within the organization that utilize `mistune` for processing untrusted user input and prioritize those for patching.
* Implement input length limits or complexity analysis for Markdown content processed by external-facing services to mitigate potential DoS attempts if immediate patching is not possible.
