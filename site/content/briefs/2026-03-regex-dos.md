---
title: 'CVE-2026-4926: Regular Expression Denial of Service'
slug: 2026-03-regex-dos
description: CVE-2026-4926 describes a denial-of-service vulnerability due to an inefficient regular expression complexity issue when handling multiple sequential optional groups, leading to exponential growth and resource exhaustion.
date: "2026-03-27T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - denial-of-service
  - regex
  - cve
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: Application Layer Protocol
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4926
  - https://cna.openjsf.org/security-advisories.html
rules:
  - title: Detect Suspicious URI with Multiple Optional Groups
    description: Detects suspicious URIs containing multiple sequential optional groups in the query string, potentially indicating a regex DoS attack attempt.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499.001
    data_sources:
      - webserver
      - linux
  - title: Detect HTTP Requests with Excessive Optional Regex Groups
    description: This rule detects HTTP requests containing a high number of curly brace pairs in the URI, which could indicate an attempt to exploit a regex-based denial-of-service vulnerability (CVE-2026-4926).
    platform: sigma
    severity: high
    tactics:
      - denial_of_service
    techniques:
      - T1499
    data_sources:
      - webserver
      - linux
rules_count: 2
---

CVE-2026-4926 exposes a denial-of-service vulnerability stemming from inefficient regular expression complexity. This flaw arises when a regular expression contains multiple sequential optional groups, denoted by curly brace syntax (e.g., `{a}{b}{c}:z`). The vulnerability lies in the exponential growth of the generated regular expression, leading to excessive resource consumption and ultimately causing a denial-of-service condition. This issue was introduced prior to version 8.4.0 and poses a…
