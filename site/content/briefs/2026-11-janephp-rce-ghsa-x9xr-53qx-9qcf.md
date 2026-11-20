---
brief_id: brief-2026-11-19-janephp-rce-ghsa-x9xr-53qx-9qcf
event_id: brief-2026-11-19-janephp-rce-ghsa-x9xr-53qx-9qcf
revision: 1
activity_at: "2026-11-19T16:38:04Z"
title: 'jane-php open-api-3: PHPDoc breakout remote code execution (CVE-2026-63413)'
slug: 2026-11-janephp-rce-ghsa-x9xr-53qx-9qcf
description: The jane-php open-api-3 library improperly handles header parameter names during code generation, allowing for PHPDoc breakout and arbitrary PHP code execution upon client instantiation in versions prior to 7.12.0.
date: "2026-11-19T16:38:04Z"
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
  - cpe:2.3:a:janephp:composer_jane_php_open_api_3:*:*:*:*:*:*:*:*
tags:
  - cve-2026-63413
  - rce
  - php
vendors:
  - janephp
products:
  - composer/jane-php/open-api-3
cves:
  - id: CVE-2026-63413
    epss: 0.00312
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-x9xr-53qx-9qcf
  - https://cveawg.mitre.org/api/cve/CVE-2026-63413
---

## Overview
Jane is a set of PHP libraries that generates models and API clients from JSON Schema and OpenAPI specifications. In version composer/jane-php/open-api-3 prior to 7.12.0, the generator emits OpenAPI header parameter names verbatim into PHPDoc comment blocks. An attacker can provide a header parameter name containing a PHPDoc closing delimiter (*/) to terminate the comment block early and inject arbitrary PHP code into the class body, including a custom __construct method.

## Attack Chain
1. An attacker influences an OpenAPI document to include a malicious header parameter name.
2. The jane-php open-api-3 library generates a Client class with the malicious input embedded in a docblock.
3. Upon instantiation of the generated client, the injected PHP code executes within the context of the consuming application.

## Impact
Exploitation allows for the execution of arbitrary PHP code with the privileges of the application consuming the generated SDK.

## Recommendation
Upgrade composer/jane-php/open-api-3 to version 7.12.0 or later.
