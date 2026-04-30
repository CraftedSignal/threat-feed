---
title: GitLab GraphQL Denial of Service Vulnerability (CVE-2026-3988)
slug: 2026-03-gitlab-graphql-dos
description: CVE-2026-3988 is a denial of service vulnerability in GitLab CE/EE allowing unauthenticated users to crash instances by sending malformed GraphQL requests, affecting versions 18.5 before 18.8.7, 18.9 before 18.9.3, and 18.10 before 18.10.1.
date: "2026-03-26T12:00:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - denial-of-service
  - graphql
  - gitlab
  - cve-2026-3988
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1210
    technique_name: Exploitation of Software Vulnerabilities
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3988
  - https://about.gitlab.com/releases/2026/03/25/patch-release-gitlab-18-10-1-released/
  - https://gitlab.com/gitlab-org/gitlab/-/work_items/593140
  - https://hackerone.com/reports/3597342
rules:
  - title: Detect Suspicious GraphQL Requests
    description: Detects potentially malicious GraphQL requests based on request size and complexity.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - webserver
      - linux
  - title: Detect High Volume GraphQL Requests from Single IP
    description: Detects a high volume of GraphQL requests originating from a single IP address, indicating a potential DoS attempt.
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

CVE-2026-3988 is a denial-of-service (DoS) vulnerability affecting GitLab CE/EE. The vulnerability resides in the processing of GraphQL requests and stems from improper input validation. An unauthenticated attacker can exploit this flaw by sending specially crafted GraphQL requests, causing the GitLab instance to become unresponsive, effectively denying service to legitimate users. The affected versions include all versions from 18.5 before 18.8.7, 18.9 before 18.9.3, and 18.10 before 18.10.1…
