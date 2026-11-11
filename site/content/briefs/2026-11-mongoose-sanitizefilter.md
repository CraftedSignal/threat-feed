---
brief_id: brief-2026-11-11-mongoose-sanitizefilter
event_id: brief-2026-11-11-mongoose-sanitizefilter
revision: 1
activity_at: "2026-11-11T02:05:28Z"
title: 'Mongoose: Connection-level sanitizeFilter bypass (CVE-2026-125119)'
slug: 2026-11-mongoose-sanitizefilter
description: A bug in Mongoose allows MongoDB query selector injection due to the failure of connection-level sanitizeFilter configurations to apply, potentially enabling unauthorized record access.
date: "2026-11-11T02:05:28Z"
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
  - cpe:2.3:a:mongoose:mongoose:*:*:*:*:*:*:*:*
tags:
  - web-application
  - database-security
  - injection
  - mongoose
  - mongodb
vendors:
  - Mongoose
products:
  - Mongoose (>= 6.0.0, < 6.13.12)
  - Mongoose (>= 7.0.0, < 7.8.13)
  - Mongoose (>= 8.0.0, < 8.24.7)
  - Mongoose (>= 9.0.0, < 9.11.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An application that relies on the connection-level option and passes an attacker-controlled object into a filter therefore remains open to selector injection
    confidence_band: high
cves:
  - id: CVE-2026-125119
    cvss: 7.5
    epss: 0.00541
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-gg4r-jv3p-qx3c
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Mongoose to the versions specified in the affected products section.
      owner: IT Operations
      due: 48h
      evidence: Source notes version-specific vulnerabilities for 6.x, 7.x, 8.x, and 9.x.
  hunt_leads:
    - lead: Identify applications using connection-level sanitizeFilter and query parameters containing MongoDB operator objects.
      technique_id: T1190
      data_needed:
        - Application logs capturing raw query filter structures
        - Web server access logs capturing POST bodies
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Applications relying on connection-level config remain open to selector injection
  mitigation_plan:
    - priority: immediate
      action: Implement global or query-level sanitizeFilter as a temporary workaround.
      owner: IT Operations
      addresses: CVE-2026-125119
      evidence: Users that set sanitizeFilter globally or on specific queries are not affected
---

Mongoose fails to apply the sanitizeFilter security option when configured at the connection level via `mongoose.connect()` or `createConnection()`. While the connection reports the option as enabled, internal query casting logic fails to reference the configuration, rendering it ineffective. Applications relying on this setting to mitigate query selector injection remain vulnerable to attacks where malicious operators, such as `{ $ne: null }`, are passed into query filters. This issue affects Mongoose versions 6.x, 7.x, 8.x, and 9.x.

## Impact
Attackers can bypass application-level authentication and data filtering by injecting MongoDB query operators into user-controlled input fields. For instance, passing an operator object as a password or username value can cause the database to return documents that should otherwise be restricted.

## Recommendation
- Upgrade Mongoose to a patched version: v6.13.12, v7.8.13, v8.24.7, or v9.11.4.
- Until patching is possible, shift from connection-level configuration to global or query-level sanitization:
 - Use global settings: `mongoose.set('sanitizeFilter', true)`.
 - Use query-level settings: `Model.find().sanitizeFilter(true)`.
- Audit existing application logic for dependencies on connection-level security configurations.
