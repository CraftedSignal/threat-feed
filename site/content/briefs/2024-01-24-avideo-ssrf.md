---
title: AVideo Unauthenticated Server-Side Request Forgery Vulnerability
slug: 2024-01-24-avideo-ssrf
description: AVideo versions up to 26.0 are vulnerable to an unauthenticated server-side request forgery (SSRF) vulnerability in the `plugin/Live/test.php` endpoint, allowing attackers to make the server send arbitrary HTTP requests, potentially exposing internal resources and cloud metadata.
date: "2026-03-23T17:16:51Z"
severities:
  - critical
tags:
  - ssrf
  - avideo
  - cve-2026-33502
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33502
rules:
  - title: Detect AVideo SSRF Attempt via plugin Live Test
    description: Detects potential SSRF attempts targeting the AVideo plugin/Live/test.php endpoint by looking for suspicious URL parameters.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo SSRF Attempt via Cloud Metadata Access
    description: Detects potential SSRF attempts resulting in access to cloud metadata endpoints.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AVideo, an open-source video platform, is affected by a critical unauthenticated Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-33502) in versions up to and including 26.0. The vulnerability exists within the `plugin/Live/test.php` file. An attacker can exploit this flaw to force the AVideo server to make HTTP requests to arbitrary URLs.  Successful exploitation allows attackers to probe internal network services, potentially accessing sensitive internal HTTP resources, cloud…
