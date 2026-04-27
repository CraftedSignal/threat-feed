---
title: Immich Stored XSS Vulnerability in 360° Panorama Viewer (CVE-2026-35455)
slug: 2024-01-immich-xss
description: A stored cross-site scripting (XSS) vulnerability in Immich versions before 2.7.0 allows authenticated users to inject arbitrary JavaScript via crafted equirectangular images, leading to session hijacking, data exfiltration, and unauthorized access.
date: "2026-04-08T19:25:24Z"
severities:
  - high
tags:
  - immich
  - xss
  - cve-2026-35455
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-35455
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35455
rules:
  - title: Detect Suspicious Immich Panorama Requests
    description: Detects potential exploitation of the Immich XSS vulnerability (CVE-2026-35455) by identifying suspicious requests to the panorama viewer with potential XSS payloads in the URL.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Possible XSS Attempts via URI
    description: Detects possible XSS attempts via requests with javascript in the URI
    platform: sigma
    severity: medium
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.001
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Immich, a self-hosted photo and video management solution, is vulnerable to a stored Cross-Site Scripting (XSS) attack.  Specifically, versions prior to 2.7.0 are susceptible. An authenticated attacker can exploit the 360° panorama viewer by uploading a specially crafted equirectangular image that contains malicious text. When another user views the panorama with the OCR overlay enabled, the injected text is extracted via OCR and rendered by the panorama viewer without sanitization. This leads…
