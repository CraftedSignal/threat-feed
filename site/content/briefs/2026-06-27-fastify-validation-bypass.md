---
title: Fastify Body Schema Validation Bypass via Leading Space in Content-Type Header
slug: 2026-06-27-fastify-validation-bypass
description: Fastify v5.x is vulnerable to a body schema validation bypass, allowing attackers to circumvent request body validation by prepending a single space to the Content-Type header, potentially compromising data integrity and security constraints.
date: "2026-04-15T19:26:39Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - fastify
  - validation-bypass
  - webserver
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Defense Evasion
cves:
  - id: CVE-2026-33806
    cvss: 7.5
    epss: 0.00043
  - id: CVE-2025-32442
    cvss: 7.5
    epss: 0.00488
references:
  - https://github.com/advisories/GHSA-247c-9743-5963
rules:
  - title: Detect Fastify Validation Bypass Attempt
    description: Detects attempts to bypass Fastify validation by prepending a space to the Content-Type header.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Fastify Validation Bypass Attempt - Generic Content Type
    description: Detects attempts to bypass Fastify validation by prepending a space to the Content-Type header for any content type.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Fastify v5.x (specifically versions 5.3.2 through 5.8.4) contains a vulnerability where request body validation schemas specified via `schema.body.content` can be bypassed by prepending a single space character (`\x20`) to the `Content-Type` header. This flaw, assigned CVE-2026-33806, arises from inconsistent handling of the Content-Type header during parsing and validation.  The body is parsed correctly as JSON, but schema validation is skipped entirely. This is a regression introduced by commit `f3d2bcb` (April 18, 2025), a fix for CVE-2025-32442. This vulnerability allows attackers to send malicious payloads that bypass intended data integrity and security checks.

## Attack Chain

1.  The attacker identifies a Fastify application using `schema.body.content` for request body validation.
2.  The attacker crafts a malicious HTTP POST request with a JSON payload designed to violate the validation schema (e.g., exceeding allowed amount or injecting invalid admin value).
3.  The attacker prepends a single space character to the `Content-Type` header (e.g., ` Content-Type: application/json`).
4.  The Fastify server parses the `Content-Type` header using `lib/validation.js` which splits the string, resulting in an empty string content type.
5.  The server fails to locate a validator associated with the empty string content type.
6.  Request body validation is skipped, and the malicious payload is processed by the application.
7.  The application processes the invalid data, potentially leading to unauthorized actions or data corruption.
8.  The attacker achieves their objective, such as transferring an excessive amount, manipulating data, or gaining unauthorized privileges.

## Impact

This vulnerability affects Fastify applications using `schema.body.content` for request body validation. By prepending a single space to the Content-Type header, attackers can bypass these validations. Successful exploitation allows an attacker to inject malicious payloads, leading to data corruption, unauthorized access, or other security breaches. While the exact number of victims is unknown, any application within the vulnerable version range is susceptible. This vulnerability requires no authentication and has zero complexity — it is a single-character modification to an HTTP header.

## Recommendation

*   Apply the recommended fix by adding `trimStart()` before the split in `getEssenceMediaType` within the Fastify framework to address CVE-2026-33806.
*   Deploy the Sigma rule "Detect Fastify Validation Bypass Attempt" to your SIEM to identify attempts to exploit this vulnerability by monitoring for requests with leading spaces in the Content-Type header.
*   Upgrade Fastify to a version beyond 5.8.4 to mitigate CVE-2026-33806.
*   Review all Fastify routes that use `schema.body.content` for potential vulnerabilities related to content-type validation.
