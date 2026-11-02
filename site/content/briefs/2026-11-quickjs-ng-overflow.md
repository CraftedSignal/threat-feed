---
brief_id: brief-2026-11-02-quickjs-ng-overflow
event_id: brief-2026-11-02-quickjs-ng-overflow
revision: 1
activity_at: "2026-11-02T15:50:38Z"
title: 'QuickJS-NG: Heap buffer overflow in js_proxy_get_own_property_names (CVE-2026-120438)'
slug: 2026-11-quickjs-ng-overflow
description: QuickJS-NG before 0.16.0 contains an integer overflow in the js_proxy_get_own_property_names function that can lead to heap buffer overflows and potential code execution on 32-bit hosts via malicious Proxy ownKeys traps.
date: "2026-11-02T15:50:38Z"
lastmod: "2026-11-02T15:50:45Z"
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
  validation_status: Source verified
cpes:
  - cpe:2.3:a:quickjs-ng:quickjs-ng:*:*:*:*:*:*:*:*
  - cpe:2.3:a:quickjs-ng_project:quickjs-ng:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - memory-corruption
  - remote-code-execution
vendors:
  - QuickJS-NG
products:
  - QuickJS-NG (< 0.16.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers running JavaScript can return a large array-like object from a Proxy ownKeys trap to wrap the allocation size, causing crashes or potential code execution.
    confidence_band: high
cves:
  - id: CVE-2026-120438
    cvss: 7.8
    kev_status: "false"
  - id: CVE-2026-120439
    cvss: 7
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120438
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120439
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all applications using QuickJS-NG and upgrade to 0.16.0
      owner: IT Operations
      due: 72h
      evidence: QuickJS-NG before 0.16.0 contains an integer overflow
  hunt_leads:
    - lead: Monitor for application crashes occurring within environments that process untrusted JavaScript or use embedded script engines
      technique_id: T1203
      data_needed:
        - Application crash logs
        - Error reporting logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: wrapping the allocation size and writing indices past the buffer to crash
  mitigation_plan:
    - priority: immediate
      action: Upgrade QuickJS-NG to version 0.16.0 or later
      owner: IT Operations
      addresses: CVE-2026-120438
      evidence: NVD advisory identifies version 0.16.0 as the fix
    - priority: immediate
      action: Upgrade QuickJS-NG to 0.16.0 or later
      owner: IT Operations
      addresses: CVE-2026-120439
      evidence: QuickJS-NG before 0.16.0 contains an integer overflow
updates:
  - at: "2026-11-02T15:50:45Z"
    level: L2
    summary: added coverage for QuickJS-NG (< 0.16.0)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-120439
---

QuickJS-NG versions prior to 0.16.0 contain an integer overflow vulnerability in the `js_proxy_get_own_property_names()` function within `quickjs.c`. The vulnerability is triggered when a JavaScript Proxy object defines an `ownKeys` trap that returns a large array-like object. On 32-bit architectures, this leads to an integer overflow during memory allocation calculations, resulting in a heap buffer overflow. This can be leveraged to cause application crashes or arbitrary code execution.

## Impact
Successful exploitation may allow for denial of service (application crashes) or arbitrary code execution in the context of the QuickJS-NG engine. The vulnerability is specifically constrained to 32-bit host environments.

## Recommendation
- Update QuickJS-NG to version 0.16.0 or later to include the fix for CVE-2026-120438.
- Inventory environments utilizing QuickJS-NG, prioritizing 32-bit architecture deployments for immediate patching.
