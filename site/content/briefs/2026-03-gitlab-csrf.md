---
title: GitLab GraphQL CSRF Vulnerability (CVE-2026-3857)
slug: 2026-03-gitlab-csrf
description: CVE-2026-3857 describes a vulnerability in GitLab CE/EE versions 17.10 before 18.8.7, 18.9 before 18.9.3, and 18.10 before 18.10.1, where an unauthenticated user can execute arbitrary GraphQL mutations on behalf of authenticated users due to insufficient CSRF protection, potentially leading to data modification or privilege escalation.
date: "2026-03-26T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - gitlab
  - csrf
  - cve-2026-3857
  - graphql
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1204
    technique_name: User Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3857
  - https://about.gitlab.com/releases/2026/03/25/patch-release-gitlab-18-10-1-released/
  - https://gitlab.com/gitlab-org/gitlab/-/work_items/592828
  - https://hackerone.com/reports/3584382
rules:
  - title: Detect GitLab GraphQL CSRF Attempt via Referer
    description: Detects potential CSRF attacks against GitLab GraphQL endpoint based on Referer header anomalies. An attacker hosted page would trigger this.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1204.001
    data_sources:
      - webserver
      - linux
  - title: Detect GitLab GraphQL CSRF via Missing Referer
    description: Detects potential CSRF attacks against GitLab GraphQL endpoint based on missing Referer header. Direct access or script-based requests would trigger this.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1204.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

GitLab has addressed a critical security flaw, identified as CVE-2026-3857, within its Community Edition (CE) and Enterprise Edition (EE). This vulnerability impacts GitLab instances running versions 17.10 up to, but not including, 18.8.7, versions 18.9 up to 18.9.3, and versions 18.10 up to 18.10.1.  The core issue lies in insufficient Cross-Site Request Forgery (CSRF) protection when handling GraphQL mutations. An unauthenticated attacker could exploit this by crafting malicious web pages…
