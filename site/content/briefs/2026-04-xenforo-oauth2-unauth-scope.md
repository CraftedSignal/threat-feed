---
title: XenForo OAuth2 Unauthorized Scope Request Vulnerability
slug: 2026-04-xenforo-oauth2-unauth-scope
description: XenForo before 2.3.5 allows OAuth2 client applications to request unauthorized scopes, potentially allowing client applications to gain access beyond their intended authorization level due to improper authorization checks.
date: "2026-04-01T01:16:40Z"
severities:
  - high
tags:
  - cve-2025-71278
  - oauth2
  - xenforo
  - incorrect-authorization
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2025-71278
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71278
  - https://www.vulncheck.com/advisories/xenforo-oauth2-unauthorized-scope-request
  - https://xenforo.com/community/threads/xenforo-2-3-5-includes-security-fix-add-ons-released.228812/
ioc_counts:
  email: 1
  url: 1
rules:
  - title: Detect Suspicious OAuth2 Scope Request
    description: Detects OAuth2 authorization requests containing unusual or excessive scopes, potentially indicating an attempt to exploit CVE-2025-71278.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1588.004
    data_sources:
      - webserver
      - linux
  - title: Detect XenForo OAuth2 Admin Scope Request
    description: Detects requests containing the string 'admin' in the OAuth2 scope, which may be indicative of privilege escalation attempts in XenForo.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

XenForo, a popular forum software, has a security vulnerability (CVE-2025-71278) affecting versions prior to 2.3.5. Specifically, the vulnerability lies in the OAuth2 client application authorization process. OAuth2 clients can request scopes beyond those they are authorized to access. This vulnerability impacts any XenForo 2.3 installation utilizing OAuth2 clients prior to upgrading to version 2.3.5. Successful exploitation could allow malicious or compromised OAuth2 client applications to…
