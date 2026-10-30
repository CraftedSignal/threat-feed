---
brief_id: brief-2026-10-30-gocardless-perl-vulnerabilities
event_id: brief-2026-10-30-gocardless-perl-vulnerabilities
revision: 1
activity_at: "2026-10-30T17:22:32Z"
title: 'Business::GoCardless for Perl: Multiple vulnerabilities (CVE-2026-119036, CVE-2026-119037, CVE-2026-119038)'
slug: 2026-10-gocardless-perl-vulnerabilities
description: Business::GoCardless for Perl versions before 1.01 are vulnerable to memory exhaustion, forged webhook processing, and insufficient redirect flow validation, potentially allowing for Denial of Service and authentication bypass.
date: "2026-10-30T17:22:32Z"
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
  validation_status: Verified against oss-security disclosure
products:
  - Business::GoCardless (< 1.01)
cves:
  - id: CVE-2026-119036
    kev_status: "false"
  - id: CVE-2026-119037
    kev_status: "false"
  - id: CVE-2026-119038
    kev_status: "false"
references:
  - https://seclists.org/oss-sec/2026/q4/450
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Team
  immediate_actions:
    - action: Upgrade Business::GoCardless to 1.01 or later
      owner: IT Operations
      due: 48h
      evidence: Business::GoCardless versions before 1.01 allow memory exhaustion... accept forged webhooks... complete redirect flows without checking
  hunt_leads:
    - lead: Monitor application logs for repeated high-volume incoming webhook requests that result in application-level memory pressure
      data_needed:
        - Application logs (web server or script-level execution logs)
        - System memory usage metrics
      priority: medium
      confidence: low
      disposition: hunt_now
      evidence: Business::GoCardless versions before 1.01 for Perl allow memory exhaustion by flattening legacy webhook payloads before checking their signature
  mitigation_plan:
    - priority: immediate
      action: Upgrade Business::GoCardless to 1.01
      owner: Development Team
      addresses: CVE-2026-119036, CVE-2026-119037, CVE-2026-119038
      evidence: Business::GoCardless versions before 1.01 for Perl allow...
---

Business::GoCardless versions before 1.01 for Perl contain three distinct security vulnerabilities. CVE-2026-119036 allows for memory exhaustion by processing and flattening large webhook payloads before the signature validation is performed. CVE-2026-119037 permits the acceptance of forged webhooks if the webhook secret is not explicitly configured (i.e., is undef or empty). CVE-2026-119038 involves a failure to properly validate redirect flows, which may lead to unauthorized flow completion.

## Impact
Systems using Business::GoCardless < 1.01 to process webhooks or redirect flows are susceptible to Denial of Service (via memory exhaustion) and authentication bypass or impersonation (via forged webhooks).

## Recommendation
- Upgrade the Business::GoCardless Perl module to version 1.01 or later immediately.
- Review application configurations to ensure a non-empty, robust webhook secret is defined for all Business::GoCardless instances to mitigate CVE-2026-119037.
- Audit logs for unexpected webhook delivery patterns or incomplete/failed signature validation attempts that may indicate attempts to exploit CVE-2026-119036 or CVE-2026-119037.
