---
title: Undertow HTTP Request Smuggling Vulnerability (CVE-2026-28367)
slug: 2026-03-undertow-smuggling
description: A remote attacker can exploit CVE-2026-28367 in Undertow by sending '\r\r\r' as a header block terminator, leading to request smuggling on vulnerable proxy servers.
date: "2026-03-27T17:16:27Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - cve
  - request-smuggling
  - undertow
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28367
  - https://access.redhat.com/security/cve/CVE-2026-28367
  - https://bugzilla.redhat.com/show_bug.cgi?id=2443260
rules:
  - title: Detect Undertow HTTP Request Smuggling Attempt
    description: Detects HTTP requests that contain '\r\r\r' in the URI, potentially indicating a request smuggling attempt targeting Undertow servers.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Undertow HTTP Request Smuggling Attempt (Header)
    description: Detects HTTP requests that contain '\r\r\r' in the HTTP Header, potentially indicating a request smuggling attempt targeting Undertow servers.
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

CVE-2026-28367 is a request smuggling vulnerability found in Undertow, a flexible performant server-side Java web server. The vulnerability arises from improper handling of HTTP header block terminators. Specifically, a remote attacker can send `\r\r\r` as a header block terminator, which can be misinterpreted by certain proxy servers. This allows the attacker to potentially smuggle malicious requests, bypassing security controls and gaining unauthorized access to resources or manipulating…
