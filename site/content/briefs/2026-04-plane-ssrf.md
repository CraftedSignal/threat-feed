---
title: Plane Project Management Tool SSRF Vulnerability (CVE-2026-39843)
slug: 2026-04-plane-ssrf
description: Plane project management tool versions before 1.3.0 are vulnerable to Server-Side Request Forgery (SSRF), allowing authenticated low-privilege attackers to read internal resources by exploiting the favicon fetch functionality.
date: "2026-04-09T16:16:31Z"
severities:
  - high
tags:
  - ssrf
  - cve-2026-39843
  - plane
  - project-management
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2026-39843
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39843
rules:
  - title: Detect Plane SSRF via Internal IP Request
    description: Detects potential SSRF attempts in Plane by monitoring for HTTP requests to internal IP addresses originating from the Plane application.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
  - title: Detect Plane SSRF via Redirect to Internal IP
    description: Detects potential SSRF attempts in Plane by monitoring for HTTP redirects to internal IP addresses.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1595.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Plane is an open-source project management tool. Versions prior to 1.3.0 are vulnerable to a Server-Side Request Forgery (SSRF) vulnerability, tracked as CVE-2026-39843. This vulnerability stems from an incomplete fix for GHSA-jcc6-f9v6-f7jw. An authenticated attacker with low privileges can exploit this vulnerability by supplying a crafted HTML page containing a `<link>` tag that redirects to a private IP address when using the "Add link" functionality. The vulnerability exists within the…
