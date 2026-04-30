---
title: Salvo Web Framework Denial of Service Vulnerability (CVE-2026-33241)
slug: 2026-03-salvo-dos
description: The Salvo web framework before version 0.89.3 is vulnerable to denial of service due to unbounded memory allocation when parsing form data, enabling attackers to crash services by sending large payloads.
date: "2026-03-25T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - denial-of-service
  - web-framework
  - rust
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33241
  - https://github.com/salvo-rs/salvo/releases/tag/v0.89.3
  - https://github.com/salvo-rs/salvo/security/advisories/GHSA-pp9r-xg4c-8j4x
rules:
  - title: Detect Large HTTP Request Body Size
    description: Detects abnormally large HTTP request bodies, which could indicate a denial-of-service attempt exploiting CVE-2026-33241.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect Repeated POST Requests from Single IP
    description: Detects a high volume of POST requests from a single IP address within a short timeframe, potentially indicating a DoS attack against the form_data() method or Extractible macro.
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

Salvo is a Rust-based web framework. Prior to version 0.89.3, the `form_data()` method and `Extractible` macro within Salvo do not properly enforce payload size limits when parsing form data. This lack of input validation allows a remote, unauthenticated attacker to send arbitrarily large HTTP request bodies to a vulnerable server. By exploiting this vulnerability, an attacker can exhaust the server's memory resources, leading to an Out-of-Memory (OOM) condition. This results in service crashes…
