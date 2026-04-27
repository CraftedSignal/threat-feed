---
title: Chamilo LMS SSRF Vulnerability in Social Wall Feature
slug: 2026-04-chamilo-ssrf
description: A Server-Side Request Forgery (SSRF) vulnerability exists in Chamilo LMS versions prior to 1.11.38 and 2.0.0-RC.3, allowing authenticated attackers to make arbitrary HTTP requests, scan internal ports, and access cloud instance metadata via the Social Wall feature.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - chamilo
  - ssrf
  - cve-2026-31941
  - lms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-31941
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-31941
rules:
  - title: Detect Chamilo LMS Social Wall SSRF Attempt
    description: Detects attempts to exploit the SSRF vulnerability in the Chamilo LMS Social Wall feature by monitoring for suspicious URLs in the `social_wall_new_msg_main` POST parameter.
    platform: sigma
    severity: high
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1018
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Chamilo LMS Social Wall SSRF Attempt - Alternative
    description: Detects attempts to exploit the SSRF vulnerability in the Chamilo LMS Social Wall feature by monitoring for suspicious URLs in the `social_wall_new_msg_main` POST parameter.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - initial_access
    techniques:
      - T1018
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chamilo LMS, a learning management system, is vulnerable to Server-Side Request Forgery (SSRF) in versions prior to 1.11.38 and 2.0.0-RC.3. This vulnerability resides in the Social Wall feature, specifically the `read_url_with_open_graph` endpoint. By supplying a crafted URL via the `social_wall_new_msg_main` POST parameter, an authenticated attacker can force the Chamilo LMS server to make arbitrary HTTP requests. This SSRF can be leveraged to probe internal services, perform port scanning on…
