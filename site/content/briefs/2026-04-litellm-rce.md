---
brief_id: brief-2026-04-11-litellm-rce
event_id: brief-2026-04-11-litellm-rce
revision: 3
activity_at: "2026-11-21T18:54:41Z"
revision_history:
  - revision: 2
    at: "2026-11-21T18:51:38Z"
    checksum: sha256:e15d7c92aeb3233a38dda281f7e033bacac7e23b3daab0f116efcf753b810642
    summary: CISA KEV listing confirmed; corrected affected versions, authentication prerequisite, severity context, and ATT&CK mapping.
    changed_fields:
      - affected_products
      - affected_vendors
      - content
      - cpes
      - cves
      - exploitation_evidence
      - has_poc
      - iocs
      - lastmod
      - poc_references
      - priority
      - priority_score
      - priority_signals
      - references
      - rules
      - severity
      - ttps
      - updates
  - revision: 3
    at: "2026-11-21T18:54:41Z"
    checksum: sha256:25c35ee4593d44c20d1a0b1efa840432990c68d276b8b51d89b9f8ddd44a6f29
    summary: Corrected public summary to remove unsupported unauthenticated claim.
    changed_fields:
      - lastmod
      - summary
      - updates
title: LiteLLM Remote Code Execution via Bytecode Rewriting (CVE-2026-40217)
slug: 2026-04-litellm-rce
description: LiteLLM 1.81.8 through versions before 1.83.10 contain a sandbox escape at /guardrails/test_custom_code that allows proxy-admin users to execute code in the proxy process.
date: "2026-04-11T12:00:00Z"
lastmod: "2026-11-21T18:54:02Z"
type: advisory
types:
  - advisory
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2026-11-18T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:litellm:litellm:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=B01AF870-0BB7-5045-8F8B-19C856066EE7&utm_source=rss&utm_medium=rss
tags:
  - CVE-2026-40217
  - litellm
  - rce
  - bytecode-rewriting
vendors:
  - BerriAI
products:
  - LiteLLM
product_versions:
  - product: LiteLLM
    range: '>= 1.81.8, < 1.83.10'
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40217
    cvss: 8.8
    epss: 0.00277
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40217
  - https://www.x41-dsec.de/lab/advisories/x41-2026-001-litellm/
  - https://github.com/BerriAI/litellm/security/advisories/GHSA-wxxx-gvqv-xp7p
  - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  - https://sploitus.com/exploit?id=B01AF870-0BB7-5045-8F8B-19C856066EE7&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=B01AF870-0BB7-5045-8F8B-19C856066EE7&utm_source=rss&utm_medium=rss
ioc_counts:
  url: 1
rules:
  - title: Detect LiteLLM custom-code guardrail requests
    description: Detect POST requests to the LiteLLM custom-code guardrail endpoint. This is a detection lead, not proof of exploitation; the endpoint requires proxy-admin credentials in default configurations.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 1
updates:
  - at: "2026-05-19T14:00:53Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
  - at: "2026-11-21T18:38:57Z"
    level: L2
    summary: CISA KEV listing confirmed; corrected affected versions, authentication prerequisite, severity context, and ATT&CK mapping.
    sources:
      - CISA KEV
      - BerriAI advisory
  - at: "2026-11-21T18:55:00Z"
    level: L2
    summary: Corrected public summary to remove unsupported unauthenticated claim.
    sources:
      - BerriAI advisory
---

## Overview

CVE-2026-40217 is a sandbox escape in LiteLLM's custom-code guardrail. A crafted request to `POST /guardrails/test_custom_code` can escape the hand-rolled Python sandbox through bytecode-level techniques and execute arbitrary code in the LiteLLM proxy process. BerriAI says this endpoint requires a proxy-admin credential in default configurations; the vendor advisory does not describe this as unauthenticated by default. The default Docker image runs the proxy as root, increasing potential impact in that deployment.

CISA added CVE-2026-40217 to its Known Exploited Vulnerabilities catalog on 2026-11-18. This brief records the catalog listing as confirmed exploitation evidence; it does not attribute the activity to a particular actor or describe specific attacks.

## Affected versions

BerriAI's advisory lists LiteLLM versions 1.81.8 and later, before 1.83.10, as affected. Its patch guidance says to upgrade to 1.83.11 or later; follow that explicit guidance. The advisory also references release 1.83.10, so verify the vendor's fixed release guidance when planning upgrades.

## Impact and severity

Successful exploitation permits arbitrary code execution in the proxy process. The National Vulnerability Database score retained here is CVSS v3.1 8.8 (High); BerriAI's advisory gives CVSS v4.0 5.9 (Moderate) and scores privileges required as high. These scores use different CVSS versions and assumptions.

## Recommendation

* Upgrade to LiteLLM 1.83.11 or later, following BerriAI's explicit patch guidance.
* Until upgraded, block `POST /guardrails/test_custom_code` at the reverse proxy or API gateway, as BerriAI recommends.
* Restrict access to the proxy-admin credential and review access logs for requests to this endpoint.
