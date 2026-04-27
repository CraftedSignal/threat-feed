---
title: BidingCC BuildingAI SSRF Vulnerability (CVE-2026-7065)
slug: 2024-01-buildingai-ssrf
description: A server-side request forgery (SSRF) vulnerability exists in BidingCC BuildingAI up to version 26.0.1, allowing remote attackers to manipulate the `url` argument in the `uploadRemoteFile` function of `file-storage.service.ts` to conduct SSRF attacks.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - ssrf
  - cve-2026-7065
  - web-application
vendors:
  - BidingCC
products:
  - BuildingAI
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Server-Side Request Forgery (SSRF)
cves:
  - id: CVE-2026-7065
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7065
rules:
  - title: Detect BuildingAI SSRF Attempt via URL Parameter
    description: Detects attempts to exploit the SSRF vulnerability in BuildingAI by monitoring requests to the uploadRemoteFile endpoint with suspicious URL parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
  - title: Detect BuildingAI SSRF Attempt via POST Request
    description: Detects attempts to exploit the SSRF vulnerability in BuildingAI by monitoring POST requests to the uploadRemoteFile endpoint with suspicious URL parameters in the request body.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
      - linux
rules_count: 2
---

BidingCC BuildingAI, up to version 26.0.1, is vulnerable to a server-side request forgery (SSRF) attack. The vulnerability resides within the `uploadRemoteFile` function located in `packages/core/src/modules/upload/services/file-storage.service.ts`. An attacker can remotely manipulate the `url` argument passed to this function to force the server to make requests to arbitrary internal or external resources. This vulnerability has been publicly disclosed and is considered exploitable. The vendor…
