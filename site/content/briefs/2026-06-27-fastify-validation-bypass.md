---
title: Fastify Body Schema Validation Bypass via Leading Space in Content-Type Header
slug: 2026-06-27-fastify-validation-bypass
description: Fastify v5.x is vulnerable to a body schema validation bypass, allowing attackers to circumvent request body validation by prepending a single space to the Content-Type header, potentially compromising data integrity and security constraints.
date: "2026-04-15T19:26:39Z"
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

Fastify v5.x (specifically versions 5.3.2 through 5.8.4) contains a vulnerability where request body validation schemas specified via `schema.body.content` can be bypassed by prepending a single space character (`\x20`) to the `Content-Type` header. This flaw, assigned CVE-2026-33806, arises from inconsistent handling of the Content-Type header during parsing and validation.  The body is parsed correctly as JSON, but schema validation is skipped entirely. This is a regression introduced by…
