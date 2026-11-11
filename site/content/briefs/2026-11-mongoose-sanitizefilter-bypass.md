---
brief_id: brief-2026-11-11-mongoose-sanitizefilter-bypass
event_id: brief-2026-11-11-mongoose-sanitizefilter-bypass
revision: 1
activity_at: "2026-11-11T01:52:18Z"
title: 'Mongoose: countDocuments() sanitizeFilter bypass (CVE-2026-125120)'
slug: 2026-11-mongoose-sanitizefilter-bypass
description: Mongoose versions prior to the patches failed to apply the sanitizeFilter utility to countDocuments() queries, allowing potential NoSQL injection when user input is passed directly to the filter argument.
date: "2026-11-11T01:52:18Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:mongoose:mongoose:*:*:*:*:*:*:*:*
vendors:
  - Mongoose
products:
  - mongoose (< 6.13.11)
  - mongoose (>= 7.0.0, < 7.8.12)
  - mongoose (>= 8.0.0, < 8.24.3)
  - mongoose (>= 9.0.0, < 9.9.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This omission allows attackers to inject malicious query selectors into database queries if user input is passed directly to the countDocuments filter argument.
    confidence_band: high
cves:
  - id: CVE-2026-125120
    cvss: 9.8
    epss: 0.00566
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-pcrw-h46h-c93h
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Patch mongoose to 6.13.11 or later
      owner: IT Operations
      due: 48h
      evidence: Patches have been released for all supported Mongoose major release lines.
  hunt_leads:
    - lead: Identify applications using mongoose.countDocuments() with dynamic input parameters.
      technique_id: T1190
      data_needed:
        - Source code analysis
        - Application dependency inventory
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability is triggered when user input is passed directly to the countDocuments filter argument.
  mitigation_plan:
    - priority: immediate
      action: Deploy the provided middleware to enforce sanitizeFilter on countDocuments.
      owner: Detection Engineering
      addresses: CVE-2026-125120
      evidence: Workaround code snippet provided in the advisory.
---

Mongoose failed to apply the `sanitizeFilter` security utility to `countDocuments()` queries, which is designed to protect against query selector injection attacks. If an application passes unsanitized user-supplied input directly to the `countDocuments()` filter argument, an attacker may be able to inject malicious query selectors. This vulnerability is identified as CVE-2026-125120.

## Impact

Successful exploitation may allow an attacker to alter the query logic of database operations, potentially resulting in unauthorized data exposure or information disclosure depending on how the application handles the query results.

## Recommendation

Upgrade Mongoose to the following versions or later to ensure `sanitizeFilter` is applied correctly to `countDocuments()` queries:
- Upgrade to version ^9.9.2
- Upgrade to version ^8.24.3
- Upgrade to version ^7.8.12
- Upgrade to version ^6.13.11

If immediate upgrading is not possible, implement the provided middleware to enforce filtering on `countDocuments` calls as a temporary mitigation.
