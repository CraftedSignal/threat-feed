---
brief_id: brief-2026-11-19-jane-php-rce-ghsa-q8v2-3j4h-xg2p
event_id: brief-2026-11-19-jane-php-rce-ghsa-q8v2-3j4h-xg2p
revision: 1
activity_at: "2026-11-19T18:41:38Z"
title: 'jane-php open-api-3: Remote code execution via PHPDoc injection (CVE-2026-63412)'
slug: 2026-11-jane-php-rce-ghsa-q8v2-3j4h-xg2p
description: The jane-php open-api-3 library fails to sanitize query parameter names when generating PHPDoc blocks, allowing an attacker-influenced OpenAPI specification to inject arbitrary PHP code that executes upon SDK client instantiation.
date: "2026-11-19T18:41:38Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
  validation_status: test_defined
cpes:
  - cpe:2.3:a:jane_php:open_api_3:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - cve-2026-63412
  - supply-chain
vendors:
  - jane-php
products:
  - open-api-3
product_versions:
  - product: open-api-3
    range: < 7.12.0
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Exploitation requires generating a client from an attacker-influenced OpenAPI document and then using the generated SDK, and can execute arbitrary PHP with the consuming application's privileges.
    confidence_band: high
cves:
  - id: CVE-2026-63412
    epss: 0.00391
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-q8v2-3j4h-xg2p
  - https://cveawg.mitre.org/api/cve/CVE-2026-63412
action_plan:
  priority: immediate_escalation
  owners:
    - Software Supply Chain Security Team
    - Application Security Team
  immediate_actions:
    - action: Identify all projects using jane-php/open-api-3 as a dependency in composer.json.
      owner: Application Security Team
      evidence: The vulnerability is present in versions < 7.12.0.
    - action: Upgrade jane-php/open-api-3 to version 7.12.0 or later.
      owner: Development Teams
      evidence: Version 7.12.0 contains the fix for CVE-2026-63412.
  hunt_leads:
    - lead: Identify builds or CI/CD logs where OpenAPI specifications are fetched from external or untrusted sources before SDK generation.
      technique_id: T1190
      data_needed:
        - CI/CD pipeline configuration files
        - Build logs
        - Vulnerability scanner reports
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation requires generating a client from an attacker-influenced OpenAPI document.
---

## Overview
Jane open-api-3 is a PHP library used to generate models and API clients from OpenAPI specifications. Before version 7.12.0, the generator incorrectly handles query parameter names by emitting them verbatim into method docblocks. Because the library does not escape the PHPDoc closing sequence (*/), an attacker can craft an OpenAPI specification containing a parameter name with a malicious payload to terminate the comment block early. This allows the insertion of arbitrary PHP code directly into the body of the generated client class, such as a custom __construct method. This code executes with the privileges of the consuming application whenever the client is instantiated.

## Attack Chain
1. Attacker crafts a malicious OpenAPI specification containing a specifically formatted query parameter name including '*/'.
2. Attacker induces the target environment to generate a PHP API client from the malicious specification.
3. jane-php/open-api-3 generator processes the parameter name and writes the raw string into a PHPDoc block in the generated source file.
4. The injected '*/' sequence prematurely closes the PHPDoc block, allowing subsequent characters to be interpreted as raw PHP code within the class.
5. Attacker-controlled PHP code (e.g., a custom __construct method) is placed into the class body.
6. The application using the generated SDK performs an instantiation of the client (e.g., '$client = new Client();').
7. The arbitrary PHP code executes during the instantiation process, leading to remote code execution.

## Impact
Successful exploitation allows for arbitrary remote code execution within the context of the consuming application. This can lead to full system compromise, data exfiltration, or lateral movement depending on the application's environment and privileges.

## Recommendation
- Upgrade the jane-php/open-api-3 composer package to version 7.12.0 or later immediately.
- Review all OpenAPI specification sources used by development teams to ensure they originate from trusted entities, as the vulnerability relies on the ingestion of untrusted spec files.
- Audit existing generated SDK clients for unexpected code or suspicious constructors if those clients were generated using versions of open-api-3 earlier than 7.12.0.
