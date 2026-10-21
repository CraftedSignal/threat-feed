---
brief_id: brief-2026-10-21-apostrophecms-dos
event_id: brief-2026-10-21-apostrophecms-dos
revision: 1
activity_at: "2026-10-21T16:07:02Z"
title: 'ApostropheCMS: Unauthenticated resource exhaustion via @apostrophecms/import-export (CVE-2026-113711)'
slug: 2026-10-apostrophecms-dos
description: ApostropheCMS is vulnerable to an unauthenticated denial-of-service condition due to the order of operations in the import-export middleware, allowing attackers to consume server-side resources.
date: "2026-10-21T16:07:02Z"
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
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:apostrophecms:apostrophe:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apostrophecms:import-export:*:*:*:*:*:*:*:*
tags:
  - cve-2026-113711
  - denial-of-service
  - web-application
vendors:
  - ApostropheCMS
products:
  - '@apostrophecms/import-export (<= 3.6.2)'
  - apostrophe (< 4.33.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The vulnerability allows an unauthenticated remote attacker to cause server-side storage and filesystem operations that should only be reachable by authorized import users.
    confidence_band: high
cves:
  - id: CVE-2026-113711
    cvss: 7.5
    epss: 0.00527
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-86wm-68pq-5jwq
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch ApostropheCMS to versions 4.33.0 or greater
      owner: IT Operations
      due: 48h
      evidence: Maintainer patch release addressing CVE-2026-113711
  mitigation_plan:
    - priority: immediate
      action: Upgrade @apostrophecms/import-export to 3.7.0
      owner: IT Operations
      addresses: CVE-2026-113711
      evidence: Vendor patch availability
---

ApostropheCMS contains a vulnerability in the `@apostrophecms/import-export` package that allows unauthenticated remote attackers to trigger server-side resource consumption. The `bigUploadMiddleware()` is executed before authentication checks are enforced, enabling attackers to initialize chunked uploads, write data to temporary storage, and manipulate cleanup processes via the `aposBigUpload` protocol. 

This issue is tracked as CVE-2026-113711. The vulnerability is confirmed in `@apostrophecms/import-export` version 3.6.2 and `apostrophe` prior to version 4.33.0.

## Attack Chain

1. An attacker sends an unauthenticated `aposBigUpload[type]=start` request to the import endpoint.
2. The server initializes an upload ID and stores attacker-provided metadata, including a declared chunk count, without verifying user session credentials.
3. The attacker issues `aposBigUpload[type]=chunk` requests to upload arbitrary data to server-side temporary storage.
4. The attacker sends an `aposBigUpload[type]=end` request to finalize the upload.
5. The server executes `bigUploadEnd()` and begins processing the stored chunks, creating temporary files.
6. The application performs a cleanup routine, where the attacker-supplied chunk count influences the number of filesystem deletion operations performed.
7. Only after the aforementioned I/O operations are completed does the process reach the authentication check in the import handler, where the request is finally rejected.

## Impact

Successful exploitation allows unauthenticated attackers to perform unauthorized server-side storage and filesystem I/O. Repeated requests or the use of large chunk count values in the upload metadata can lead to service degradation or denial-of-service via resource exhaustion.

## Recommendation

* Upgrade `apostrophe` to version 4.33.0 or later.
* Upgrade `@apostrophecms/import-export` to version 3.7.0 or later.
* Implement strict authentication checks before calling `bigUploadMiddleware()` in all import-related routes.
* Enforce upper bounds on chunk counts and validate declared file sizes against actual data streams to mitigate potential amplification.
* Implement rate limiting and storage quotas for all upload endpoints.
