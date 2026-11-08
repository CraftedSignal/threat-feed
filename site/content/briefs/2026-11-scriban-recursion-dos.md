---
brief_id: brief-2026-11-08-scriban-recursion-dos
event_id: brief-2026-11-08-scriban-recursion-dos
revision: 1
activity_at: "2026-11-08T15:31:02Z"
title: 'Scriban: Uncontrolled recursion denial-of-service (CVE-2026-124439)'
slug: 2026-11-scriban-recursion-dos
description: Scriban and Scriban.Signed versions prior to 7.5.3 are vulnerable to uncontrolled recursion, allowing an attacker to trigger a process-terminating StackOverflowException via malicious templates.
date: "2026-11-08T15:31:02Z"
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
cpes:
  - cpe:2.3:a:scriban:scriban:*:*:*:*:*:*:*:*
vendors:
  - Scriban
products:
  - Scriban (< 7.5.3)
  - Scriban.Signed (< 7.5.3)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Attackers who can supply templates can trigger an uncatchable StackOverflowException that terminates the host process.
    confidence_band: high
cves:
  - id: CVE-2026-124439
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124439
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Scriban and Scriban.Signed to 7.5.3 or later across all internal applications.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-124439 remediation.
  hunt_leads:
    - lead: Identify .NET applications utilizing the Scriban library and monitor for process crashes or recurring StackOverflowExceptions.
      technique_id: T1499
      data_needed:
        - Application error logs (e.g., Windows Event Log / Event ID 1000)
        - Application performance monitoring (APM) crash reports
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Attackers who can supply templates can trigger an uncatchable StackOverflowException that terminates the host process.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Scriban/Scriban.Signed to version 7.5.3.
      owner: IT Operations
      addresses: CVE-2026-124439
      evidence: NVD CVE-2026-124439 details.
---

Scriban and Scriban.Signed versions prior to 7.5.3 contain uncontrolled recursion vulnerabilities. Specific flaws include postfix member, indexer, and call chains that bypass the configured `ExpressionDepthLimit`, as well as missing depth and cycle checks in array comparisons and `object.eval` calls. Successful exploitation allows an attacker who can supply templates to trigger an uncatchable `StackOverflowException`, resulting in a denial-of-service by crashing the host process.

## Impact

Successful exploitation results in the immediate termination of the host process, leading to a denial-of-service for any application utilizing the affected Scriban template engine.

## Recommendation

- Upgrade Scriban and Scriban.Signed to version 7.5.3 or later.
- Audit applications that process user-supplied templates to ensure templates originate from trusted sources.
- Monitor logs for repeated `StackOverflowException` errors within .NET applications that process user templates.
