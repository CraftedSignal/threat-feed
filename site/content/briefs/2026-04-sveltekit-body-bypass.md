---
title: '@sveltejs/adapter-node BODY_SIZE_LIMIT Bypass Vulnerability'
slug: 2026-04-sveltekit-body-bypass
description: A vulnerability exists in @sveltejs/adapter-node where requests could bypass the `BODY_SIZE_LIMIT` on SvelteKit applications, potentially leading to denial of service.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - sveltekit
  - denial-of-service
  - vulnerability
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
cves:
  - id: CVE-2026-40073
references:
  - https://github.com/advisories/GHSA-2crg-3p73-43xp
  - https://github.com/sveltejs/kit/releases/tag/%40sveltejs%2Fkit%402.57.1
rules:
  - title: Detect Large HTTP Request Size
    description: Detects unusually large HTTP request sizes, potentially indicating a BODY_SIZE_LIMIT bypass attempt.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect POST requests exceeding a specific size to any URI
    description: Detect POST requests with Content-Length header exceeding a threshold.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A high-severity vulnerability, CVE-2026-40073, affects SvelteKit applications using `@sveltejs/adapter-node` versions 2.57.0 and earlier. This vulnerability allows requests to bypass the intended `BODY_SIZE_LIMIT`, potentially leading to resource exhaustion and denial-of-service conditions. The bypass occurs specifically within the adapter itself and does not impact body size limits enforced by other layers such as Web Application Firewalls (WAFs), gateways, or platform-level configurations…
