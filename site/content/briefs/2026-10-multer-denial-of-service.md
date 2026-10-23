---
brief_id: brief-2026-10-23-multer-denial-of-service
event_id: brief-2026-10-23-multer-denial-of-service
revision: 1
activity_at: "2026-10-23T04:18:39Z"
title: 'OpenJS Foundation multer: Unauthenticated process crash via async fileFilter (CVE-2026-113872)'
slug: 2026-10-multer-denial-of-service
description: An unauthenticated attacker can crash Node.js applications using multer versions 2.0.0 through 2.4.0 by sending crafted multipart requests that trigger uncaught exceptions in the busboy parser after request teardown.
date: "2026-10-23T04:18:39Z"
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
  validation_status: Patch confirmed by OpenJS Foundation.
cpes:
  - cpe:2.3:a:openjsf:multer:2.0.0:*:*:*:*:node.js:*:*
  - cpe:2.3:a:openjsf:multer:2.1.0:*:*:*:*:node.js:*:*
  - cpe:2.3:a:openjsf:multer:2.2.0:*:*:*:*:node.js:*:*
  - cpe:2.3:a:openjsf:multer:2.3.0:*:*:*:*:node.js:*:*
  - cpe:2.3:a:openjsf:multer:2.4.0:*:*:*:*:node.js:*:*
vendors:
  - OpenJS Foundation
products:
  - multer (2.0.0 to 2.4.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    subtechnique_id: T1499.004
    subtechnique_name: Application or System Exploitation
    evidence: A single unauthenticated upload request can crash the whole Node.js process of any Express app that uses multer with an asynchronous fileFilter.
    confidence_band: high
cves:
  - id: CVE-2026-113872
    cvss: 7.5
    kev_status: "false"
references:
  - https://github.com/expressjs/multer/security/advisories/GHSA-q7qp-rjg7-q26m
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113872
  - https://sploitus.com/exploit?id=0313CB25-1DC7-5562-8E69-38840C5DF6C3
  - https://sploitus.com/exploit?id=0313CB25-1DC7-5562-8E69-38840C5DF6C3&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all Node.js applications using multer to version 2.5.0 or later
      owner: IT Operations
      due: 48h
      evidence: GitHub advisory GHSA-q7qp-rjg7-q26m states multer 2.5.0 contains the fix.
  mitigation_plan:
    - priority: immediate
      action: Refactor asynchronous fileFilter logic to be synchronous
      owner: Development Team
      addresses: CVE-2026-113872
      evidence: Source notes workaround if upgrade is impossible.
---

A denial-of-service vulnerability exists in the multer middleware for Node.js (CVE-2026-113872). The vulnerability occurs when multer is configured with an asynchronous `fileFilter` and processes requests containing multiple files. If an earlier part of the multipart request triggers an error, the request teardown removes event listeners from the underlying busboy parser. If a subsequent asynchronous `fileFilter` completes after the teardown, it forces the parser to resume processing a truncated or malformed body. This triggers an error on the busboy instance that no longer has an error listener, resulting in an uncaught exception that terminates the Node.js process.

## Attack Chain
1. Attacker identifies an Express application using `multer` (>= 2.0.0, <= 2.4.0) with an asynchronous `fileFilter`.
2. Attacker initiates a multipart/form-data request containing at least two file parts.
3. Attacker triggers a failure on the first file part (e.g., via the `fileFilter` logic) to initiate the request teardown process.
4. The application performs teardown, calling `busboy.removeAllListeners()`.
5. The attacker's second, pending `fileFilter` completes after the teardown occurs.
6. The `fileStream.resume()` call triggers the busboy parser to process the buffered input.
7. The parser encounters an error (e.g., unexpected end of form) and emits it on the busboy instance.
8. Due to the removed listeners, the error becomes an uncaught exception, crashing the Node.js process.

## Impact
The vulnerability allows an unauthenticated remote attacker to cause a complete service disruption by crashing the target Node.js process with a single crafted HTTP request.

## Recommendation
- Upgrade `multer` to version `2.5.0` or later immediately.
- If upgrading is not immediately possible, refactor the `fileFilter` to be synchronous and move any asynchronous validation logic into the route handler following the multer middleware.
