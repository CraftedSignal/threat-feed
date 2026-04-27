---
title: Rack::Static Information Disclosure Vulnerability (CVE-2026-34785)
slug: 2026-04-rack-static-disclosure
description: Rack versions prior to 2.2.23, 3.1.21, and 3.2.6 are vulnerable to information disclosure due to improper static file serving via a prefix matching issue in Rack::Static.
date: "2026-04-02T17:16:24Z"
severities:
  - medium
tags:
  - rack
  - information-disclosure
  - CVE-2026-34785
  - ruby
  - webserver
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
cves:
  - id: CVE-2026-34785
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34785
rules:
  - title: Detect Suspicious Rack Static File Access
    description: Detects attempts to access potentially sensitive files via Rack::Static by checking for common sensitive file extensions within configured static directories.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Rack Static File Access - Backup Files
    description: Detects access to backup files within Rack static directories.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1595.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Rack, a modular Ruby web server interface, is susceptible to an information disclosure vulnerability in versions prior to 2.2.23, 3.1.21, and 3.2.6. The flaw resides in the Rack::Static middleware component, which uses a simple string prefix check to determine if a request should be served as a static file. When configured with URL prefixes, such as "/css", Rack::Static incorrectly matches any request path starting with "/css", potentially serving unintended files like "/css-config.env" or…
