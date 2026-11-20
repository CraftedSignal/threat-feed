---
brief_id: brief-2026-11-20-janephp-ssrf-lfi-ghsa-c3cj-3p6p-j822
event_id: brief-2026-11-20-janephp-ssrf-lfi-ghsa-c3cj-3p6p-j822
revision: 1
activity_at: "2026-11-20T02:04:32Z"
title: 'jane-php: OpenAPI $ref resolution SSRF and path traversal (CVE-2026-63415)'
slug: 2026-11-janephp-ssrf-lfi-ghsa-c3cj-3p6p-j822
description: The jane-php library is vulnerable to SSRF and LFI via unsanitized $ref resolution during code generation, allowing attacker-controlled OpenAPI documents to leak local files or perform requests to internal services.
date: "2026-11-20T02:04:32Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:janephp:janephp:*:*:*:*:*:*:*:*
tags:
  - attack.initial-access
  - attack.execution
vendors:
  - jane-php
products:
  - composer/jane-php/open-api-3
cves:
  - id: CVE-2026-63415
    epss: 0.00348
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-c3cj-3p6p-j822
  - https://cveawg.mitre.org/api/cve/CVE-2026-63415
---

## Overview

jane-php, a set of PHP libraries for generating models and API clients from JSON Schema and OpenAPI specifications, is vulnerable to Server-Side Request Forgery (SSRF) and Local File Inclusion (LFI). Prior to version 7.12.0, the `Reference.php::doResolve` method passes an attacker-controlled OpenAPI `$ref` target to `file_get_contents` without restricting the scheme or the resolved local path.

## Attack Chain

An attacker provides a malicious OpenAPI specification during the code generation process. When `jane-php` parses the `$ref` field, the `doResolve` function executes `file_get_contents` on the provided URI. 
- If the URI is an HTTP/HTTPS scheme, it performs an outgoing request (SSRF). 
- If the URI is a local path, it attempts to read files (LFI), including traversal using `..`.
- The retrieved content is inlined into the generated output.

## Impact

Exploitation occurs during code generation or CI processing. It can lead to the disclosure of local files (including JSON/YAML) or interactions with internal services, with the results appearing in the generated code or build logs.

## Recommendation

Upgrade `composer/jane-php/open-api-3` to version 7.12.0 or later, which addresses the issue.
