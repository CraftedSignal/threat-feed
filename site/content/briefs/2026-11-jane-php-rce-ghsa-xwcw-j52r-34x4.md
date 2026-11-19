---
brief_id: brief-2026-11-19-jane-php-rce-ghsa-xwcw-j52r-34x4
event_id: brief-2026-11-19-jane-php-rce-ghsa-xwcw-j52r-34x4
revision: 1
activity_at: "2026-11-19T16:38:13Z"
title: 'Jane open-api-3: Arbitrary PHP Code Injection (CVE-2026-63411)'
slug: 2026-11-jane-php-rce-ghsa-xwcw-j52r-34x4
description: The jane-php/open-api-3 library improperly sanitizes parameter descriptions in generated PHPDoc comments, allowing an attacker to inject arbitrary PHP code that executes during client instantiation.
date: "2026-11-19T16:38:13Z"
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
  - cpe:2.3:a:janephp:janephp:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - php
  - cwe-94
vendors:
  - janephp
products:
  - janephp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Injecting `*/ public function __construct(){ <code> } /*` adds an attacker-controlled __construct to the generated Client class, which runs when the client is instantiated -> RCE (CWE-94).
cves:
  - id: CVE-2026-63411
    epss: 0.00312
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-xwcw-j52r-34x4
  - https://cveawg.mitre.org/api/cve/CVE-2026-63411
action_plan:
  hunt_leads:
    - lead: Identify generated PHP client classes that contain unexpected 'public function __construct()' definitions or unusual block comment closures within 'jane-php' generated source files. Scan for the presence of '*/ public function' patterns in docblocks which indicate an escaped PHPDoc breakout leading to arbitrary code injection.
      technique_id: T1059
      data_needed:
        - File system integrity monitoring
        - Source code repository audit logs
        - Application server file contents
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Injecting */ public function __construct(){ <code> } /* adds an attacker-controlled __construct to the generated Client class, which runs when the client is instantiated
---

## Overview

The jane-php/open-api-3 library, used for generating PHP models and API clients from JSON Schema and OpenAPI specifications, is vulnerable to arbitrary PHP code injection (CWE-94). The generator emits OpenAPI parameter descriptions verbatim within PHPDoc docblocks. An attacker can use a `*/` sequence in a parameter description to prematurely close the comment block and inject arbitrary PHP code into the class body of the generated client.

## Attack Chain

1. An attacker influences the OpenAPI specification used by a target to generate a PHP SDK.
2. The `jane-php/open-api-3` generator processes the malicious specification and embeds the tainted parameter description into the generated code.
3. Upon instantiation of the generated client class, the injected PHP code (e.g., a custom `__construct` method) is executed with the privileges of the consuming application.

## Impact

Successful exploitation allows arbitrary PHP code execution. The impact is equivalent to the privileges of the application consuming the generated SDK.

## Recommendation

Upgrade `jane-php/open-api-3` to version 7.12.0 or later, which resolves the vulnerability by ensuring proper sanitization of PHPDoc comments.
