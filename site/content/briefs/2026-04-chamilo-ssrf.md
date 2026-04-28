---
title: Chamilo LMS Unauthenticated SSRF Vulnerability
slug: 2026-04-chamilo-ssrf
description: An unauthenticated server-side request forgery (SSRF) vulnerability exists in Chamilo LMS versions prior to 2.0.0-RC.3, allowing attackers to probe internal network services, access cloud metadata, or trigger state-changing operations on internal services.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - chamilo
  - ssrf
  - cve-2026-34160
  - lms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-34160
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34160
ioc_counts:
  ip: 1
rules:
  - title: Detect Chamilo LMS SSRF Attempt via Package URL
    description: Detects potential SSRF attempts in Chamilo LMS by monitoring the package-url parameter for suspicious values like internal IP addresses or cloud metadata endpoints.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Chamilo LMS PENS Plugin Access
    description: Detects access to the Chamilo LMS PENS plugin endpoint. This rule can be used in conjunction with other rules to identify potential SSRF exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Chamilo LMS, an open-source learning management system, is vulnerable to a Server-Side Request Forgery (SSRF) flaw in versions prior to 2.0.0-RC.3. The vulnerability resides within the PENS plugin endpoint at `public/plugin/Pens/pens.php`, which is accessible without authentication. The `package-url` parameter is not properly validated, allowing an attacker to specify arbitrary URLs for the server to fetch using curl. This enables unauthenticated attackers to probe internal network services…
