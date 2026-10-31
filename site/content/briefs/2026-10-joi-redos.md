---
brief_id: brief-2026-10-29-joi-redos
event_id: brief-2026-10-29-joi-redos
revision: 2
activity_at: "2026-10-31T03:18:47Z"
revision_history:
  - revision: 2
    at: "2026-10-31T03:18:47Z"
    checksum: sha256:f64df6f083da159281114dfcedb83053000abbaefcb657143e1d7ebd413d45b0
    summary: poc_available
    changed_fields:
      - claim_state
      - cves
      - has_poc
      - lastmod
      - references
      - updates
    source_urls:
      - https://github.com/advisories/GHSA-4528-x5fx-h6hg
title: 'joi: Regular expression denial of service in email validation (CVE-2026-118772)'
slug: 2026-10-joi-redos
description: The joi JavaScript validation library is vulnerable to a Regular Expression Denial of Service (ReDoS) attack when processing inputs via the email() rule with the multiple option enabled.
date: "2026-10-29T20:40:38Z"
lastmod: "2026-10-31T03:18:06Z"
type: advisory
claim_state: <nil>
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
  - cpe:2.3:a:hapi:joi:*:*:*:*:*:node.js:*:*
has_poc: true
vendors:
  - Hapi
products:
  - joi (17.1.1-17.13.8)
  - joi (18.0.0-18.3.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Applications that validate attacker-controlled values with the multiple option and no effective prior length limit can have the Node.js event loop blocked for seconds by one request, preventing other work.
    confidence_band: high
cves:
  - id: CVE-2026-118772
    cvss: 7.5
    epss: 0.00467
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118772
  - https://github.com/advisories/GHSA-4528-x5fx-h6hg
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Update joi dependency to 17.13.9 or 18.3.1
      owner: IT Operations
      due: 48h
      evidence: This vulnerability is fixed in versions 17.13.9 and 18.3.1.
  hunt_leads:
    - lead: Identify long-running HTTP request execution times in Node.js application logs
      technique_id: T1499
      data_needed:
        - Web server request duration (latency)
        - Request body size
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Applications ... can have the Node.js event loop blocked for seconds by one request
  mitigation_plan:
    - priority: immediate
      action: Upgrade joi library to 17.13.9 or 18.3.1
      owner: Application Security
      addresses: CVE-2026-118772
      evidence: This vulnerability is fixed in versions 17.13.9 and 18.3.1.
updates:
  - at: "2026-10-31T03:18:06Z"
    level: L2
    summary: poc_available
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-4528-x5fx-h6hg
---

A Regular Expression Denial of Service (ReDoS) vulnerability exists in the joi library when using the 'Joi.string().email({ multiple: true })' validation rule. The flaw stems from a regular expression used for separator handling, which exhibits quadratic time complexity when processing strings containing long sequences of whitespace without valid separators. This can lead to event loop blocking in Node.js applications, resulting in a denial of service. The vulnerability is present in versions 17.1.1 through 17.13.8, and 18.0.0 through 18.3.0.

## Impact
Successful exploitation allows an attacker to block the Node.js event loop for several seconds per request. Because the vulnerability can bypass existing string length limitations (such as .max() when abortEarly is set to false), it enables resource exhaustion via a single, specially crafted HTTP request.

## Recommendation
- Update the joi package to version 17.13.9 or 18.3.1 immediately to remediate the vulnerable regular expression logic.
- Audit application code using 'Joi.string().email({ multiple: true })' to ensure input length is constrained prior to validation.
- Monitor Node.js event loop lag and request processing times as indicators of potential exploitation attempts.
