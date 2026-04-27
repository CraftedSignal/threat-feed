---
title: OpenClaw Cross-Site Request Forgery Vulnerability
slug: 2026-04-openclaw-csrf
description: OpenClaw before 2026.3.31 is vulnerable to cross-site request forgery (CSRF) attacks due to missing browser-origin validation in HTTP operator endpoints when operating in trusted-proxy mode, allowing attackers to perform unauthorized actions.
date: "2026-04-24T12:00:00Z"
severities:
  - medium
tags:
  - csrf
  - web-application
  - vulnerability
vendors:
  - OpenClaw
products:
  - OpenClaw
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1565
    technique_name: Web Session Hijacking
cves:
  - id: CVE-2026-41347
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41347
  - https://github.com/openclaw/openclaw/commit/6b3f99a11f4d070fa5ed2533abbb3d7329ea4f0d
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-mhr7-2xmv-4c4q
  - https://www.vulncheck.com/advisories/openclaw-cross-site-request-forgery-via-missing-browser-origin-validation-in-http-operator-endpoints
rules:
  - title: Detect HTTP Requests to Operator Endpoints Without Origin Header
    description: Detects HTTP requests to OpenClaw operator endpoints lacking an Origin header, indicative of potential CSRF attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1565
    data_sources:
      - webserver
      - linux
  - title: Detect POST Requests to Operator Endpoints From Unrelated Referer
    description: Detects POST requests to OpenClaw operator endpoints with a Referer header pointing to a different domain.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1565
    data_sources:
      - webserver
      - linux
rules_count: 2
---

OpenClaw before version 2026.3.31 is susceptible to Cross-Site Request Forgery (CSRF) attacks. The vulnerability lies in the lack of browser-origin validation within the HTTP operator endpoints when the application operates in trusted-proxy mode. This allows an attacker to craft malicious HTTP requests originating from a user's browser to perform unauthorized actions within the OpenClaw application. Successful exploitation of this vulnerability enables attackers to execute privileged…
