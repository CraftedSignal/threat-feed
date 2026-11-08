---
brief_id: brief-2026-11-08-scriban-resource-exhaustion
event_id: brief-2026-11-08-scriban-resource-exhaustion
revision: 1
activity_at: "2026-11-08T15:30:43Z"
title: 'Scriban: Resource exhaustion via template builtins (CVE-2026-124437)'
slug: 2026-11-08-scriban-resource-exhaustion
description: Scriban versions prior to 7.5.3 are vulnerable to resource exhaustion because specific built-in functions bypass memory and CPU allocation limits, allowing malicious templates to cause denial-of-service in multi-tenant environments.
date: "2026-11-08T15:30:43Z"
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
  validation_status: Needs environment verification of template isolation constraints
cpes:
  - cpe:2.3:a:scriban:scriban:*:*:*:*:*:*:*:*
vendors:
  - Scriban
products:
  - Scriban (< 7.5.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers can submit small templates using huge format precision specifiers, shared-structure array comparison, BigInteger multiplication or exponential function recursion that ignore LoopLimit and CancellationToken, crashing or stalling multi-tenant hosts.
    confidence_band: high
cves:
  - id: CVE-2026-124437
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124437
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Scriban to version 7.5.3 or later
      owner: IT Operations
      due: 48h
      evidence: Scriban before 7.5.3 contains a resource exhaustion vulnerability
  hunt_leads:
    - lead: Monitor application process logs for abnormal thread duration or memory spikes specifically correlated with template processing requests
      technique_id: T1499
      data_needed:
        - Application performance monitoring (APM) metrics
        - Application logs capturing template execution time
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers can submit small templates [...] crashing or stalling multi-tenant hosts.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Scriban to version 7.5.3 or later
      owner: IT Operations
      addresses: CVE-2026-124437
      evidence: Scriban before 7.5.3 contains a resource exhaustion vulnerability
---

Scriban versions prior to 7.5.3 contain a resource exhaustion vulnerability. Built-in functions, specifically math.format, regex.replace, and string.escape, fail to adhere to the LimitToString allocation guard. By supplying templates with specific structures, such as high-precision specifiers, large array comparisons, or specific mathematical operations, an attacker can bypass LoopLimit and CancellationToken mechanisms. This triggers excessive CPU and memory consumption, leading to potential crashing or stalling of host processes in multi-tenant environments.

## Impact

Successful exploitation allows for denial-of-service against the host process, potentially disrupting services for all tenants on the shared host.

## Recommendation

- Upgrade Scriban to version 7.5.3 or later immediately to apply the corrected allocation guards.
- Review all user-provided templates for usage of high-precision math functions, regex operations, or complex array manipulations if an immediate upgrade is not feasible.
- Monitor host memory and CPU utilization metrics for application processes utilizing the Scriban library to identify potential resource spikes indicative of template-based exploitation.
