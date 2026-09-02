---
title: Denial of Service in Tornado via Unbounded Form Field Parsing
slug: 2026-09-tornado-dos
description: Tornado fails to restrict the number of fields parsed in application/x-www-form-urlencoded request bodies, allowing an unauthenticated attacker to cause a denial-of-service by stalling the event loop.
date: "2026-09-02T18:04:24Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:tornado:tornado:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - web-application
  - vulnerability
vendors:
  - Tornado
products:
  - Tornado (<= 6.5.7)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: A body made almost entirely of separators produces tens of millions of fields, and the parse happens on the event loop before the handler runs, so a single request stalls the whole server.
    confidence_band: high
cves:
  - id: CVE-2026-82397
    cvss: 7.5
    epss: 0.0035
references:
  - https://github.com/advisories/GHSA-mpf4-983q-p7j4
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82397
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Application Security
  immediate_actions:
    - action: Patch Tornado to 6.5.8 or later
      owner: Application Security
      due: 48h
      evidence: CVE-2026-82397 indicates a high severity vulnerability in Tornado <= 6.5.7
  mitigation_plan:
    - priority: immediate
      action: Reduce the default body buffer size (max_buffer_size) in the Tornado application configuration to a reasonable limit for expected traffic.
      owner: IT Operations
      addresses: CVE-2026-82397
      evidence: Lowering the default body cap for urlencoded specifically would help too
---

Tornado versions 6.5.7 and earlier are vulnerable to a denial-of-service (DoS) condition due to how they process application/x-www-form-urlencoded request bodies. The web framework utilizes `urllib.parse.parse_qs` to decode incoming form data but fails to implement the `max_num_fields` parameter introduced in CPython. Because Tornado is single-threaded and executes this parsing synchronously on the event loop before reaching the application handler, an attacker can send a crafted request body containing tens of millions of field separators. This forces the server process to expend significant CPU cycles on parsing, effectively stalling the event loop and blocking all other concurrent connections. The issue is exacerbated by the default 100 MB request body limit, which provides ample space for an attacker to include roughly fifty million fields in a single HTTP POST request. This vulnerability is pre-dispatch and requires no authentication, making it a critical risk for internet-facing Tornado applications.

## Attack Chain

1. Attacker identifies an internet-facing endpoint running a vulnerable Tornado version that accepts POST requests with application/x-www-form-urlencoded content.
2. Attacker crafts a malicious HTTP POST request body consisting of a large sequence (up to 100 MB) of delimiter characters (e.g., ampersands) to maximize the number of fields.
3. The request is transmitted to the target Tornado server.
4. The Tornado HTTP server reads the full request body up to the configured `max_buffer_size` (default 100 MB).
5. The server executes `tornado.web.RequestHandler._execute`, which triggers the synchronous `_parse_body` routine within the event loop.
6. The `parse_qs_bytes` function attempts to parse the unbounded number of fields using `urllib.parse.parse_qs` without a limit.
7. The process consumes high CPU while parsing the millions of fields, causing the event loop to hang and ceasing all processing of other legitimate client connections.
8. The server remains in an unresponsive state until the malicious parsing completes or the process is manually restarted.

## Impact

Successful exploitation results in a complete denial-of-service for the affected Tornado server process. Since the event loop is blocked synchronously, all legitimate users of the service will experience timeouts or connection resets. This affects any application running on Tornado that accepts POST requests, which is standard for web services, and can be executed by any unauthenticated remote attacker.

## Recommendation

1. Upgrade to a version of Tornado that includes a fix for CVE-2026-82397 (future release beyond 6.5.7).
2. Implement an application-level wrapper or middleware to validate the size and complexity of request bodies before they reach the framework's parser.
3. Review and reduce the `max_buffer_size` and request body limits for routes that do not require 100 MB of form data to mitigate the maximum possible input size for the parser.
