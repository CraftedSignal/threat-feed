---
title: Payload CMS Stored XSS Vulnerability (CVE-2026-34748)
slug: 2026-04-payloadcms-xss
description: A stored Cross-Site Scripting (XSS) vulnerability exists in Payload CMS versions prior to 3.78.0, allowing authenticated users with write access to inject malicious scripts that execute in the browsers of other users.
date: "2026-04-01T20:16:27Z"
severities:
  - medium
tags:
  - xss
  - cve-2026-34748
  - payloadcms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34748
    cvss: 8.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34748
  - https://github.com/payloadcms/payload/security/advisories/GHSA-mmxc-95ch-2j7c
rules:
  - title: Detect Script Tag Injection in HTTP Request Parameters
    description: Detects potential XSS attacks by identifying script tags within HTTP request parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Script Tag Injection in HTTP Request Body
    description: Detects potential XSS attacks by identifying script tags within HTTP request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Payload CMS is a free and open-source headless content management system. Prior to version 3.78.0, a stored Cross-Site Scripting (XSS) vulnerability (CVE-2026-34748) existed in the admin panel of @payloadcms/next. This vulnerability allows an authenticated user with write access to a collection to save malicious content, which, when viewed by another user, results in arbitrary JavaScript execution within their browser. Successful exploitation can lead to session hijacking, defacement, or other…
