---
title: Ruby on Rails Active Storage DoS Vulnerability (CVE-2026-33174)
slug: 2026-03-rails-dos
description: A denial-of-service vulnerability (CVE-2026-33174) exists in Ruby on Rails Active Storage versions prior to 8.1.2.1, 8.0.4.1, and 7.2.3.1 due to unbounded memory allocation when handling large or unbounded Range headers in proxy delivery mode.
date: "2026-03-24T00:16:28Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - rails
  - active-storage
  - dos
  - cve-2026-33174
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33174
rules:
  - title: Detect Suspicious Range Header
    description: Detects HTTP requests with unusually large Range headers, potentially indicating a DoS attack attempt against Rails Active Storage.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple Large Range Header Requests
    description: Detects multiple requests with large Range headers from the same IP address within a short time period, potentially indicating a DoS attack.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-33174 is a denial-of-service vulnerability affecting Ruby on Rails applications that utilize Active Storage. Specifically, it impacts versions prior to 8.1.2.1, 8.0.4.1, and 7.2.3.1. The vulnerability stems from the way Active Storage handles file serving through its proxy delivery mode. When processing requests with large or unbounded Range headers (e.g., `bytes=0-`), the proxy controller incorrectly loads the entire requested byte range into memory before sending it to the client…
