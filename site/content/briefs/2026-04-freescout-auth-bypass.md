---
title: FreeScout Authorization Bypass Vulnerability (CVE-2026-39384)
slug: 2026-04-freescout-auth-bypass
description: FreeScout before version 1.8.212 is vulnerable to an authorization bypass (CVE-2026-39384) due to improper validation of the `limit_user_customer_visibility` parameter during customer merging, potentially leading to unauthorized data modification and access.
date: "2026-04-07T17:16:37Z"
severities:
  - high
tags:
  - authorization-bypass
  - cve-2026-39384
  - freescout
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-39384
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39384
  - https://github.com/freescout-help-desk/freescout/commit/b395a1179117af5e2df704c6bad71feeb301b4ce
  - https://github.com/freescout-help-desk/freescout/security/advisories/GHSA-j6v9-22vq-53vh
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious Customer Merges
    description: Detects potential authorization bypass attempts during customer merges in FreeScout by monitoring for requests that manipulate the `limit_user_customer_visibility` parameter.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect FreeScout web requests
    description: Detects FreeScout web requests
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FreeScout, a PHP-based help desk and shared inbox application built on the Laravel framework, contains an authorization bypass vulnerability (CVE-2026-39384) affecting versions prior to 1.8.212. The vulnerability stems from the application's failure to properly validate the `limit_user_customer_visibility` parameter when merging customer accounts. This oversight allows an attacker with low privileges to potentially bypass intended authorization controls, leading to unauthorized modification of…
