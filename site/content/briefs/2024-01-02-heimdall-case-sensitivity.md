---
title: Heimdall Host Matching Case-Sensitivity Vulnerability
slug: 2024-01-02-heimdall-case-sensitivity
description: Heimdall performs case-sensitive host matching, which can lead to policy bypass because HTTP hostnames are case-insensitive, potentially leading to unauthorized access, data modification, or privilege escalation if the request host is part of the rule.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - defense-evasion
  - policy-bypass
  - access-control
vendors:
  - dadrus
products:
  - heimdall
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-72h4-mxfc-jx37
rules:
  - title: Detect HTTP Requests with Mixed-Case Host Headers
    description: Detects HTTP requests where the Host header contains mixed-case characters, potentially indicating an attempt to bypass case-sensitive access controls.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Usage of Insecure Heimdall Flags
    description: Detects command-line arguments indicating the use of insecure Heimdall configurations, such as skipping secure default rule enforcement.
    platform: sigma
    severity: high
    tactics:
      - configuration
    techniques:
      - T1562.001
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Heimdall, a Go-based access management system, is susceptible to a case-sensitivity vulnerability in its host matching mechanism. HTTP hostnames are case-insensitive, but Heimdall performs host matching in a case-sensitive manner. Discovered and reported in April 2026, this discrepancy can result in Heimdall failing to match a rule for a request host that differs only in letter casing. Version 0.16.0 and later enforce secure defaults and refuse to start with an "allow all" configuration unless explicitly disabled using flags like `--insecure-skip-secure-default-rule-enforcement` or `--insecure`. The vulnerability affects Heimdall versions prior to 0.17.14 and can be exploited if rule matching relies on the request host, potentially leading to unintended access control bypass.

## Attack Chain

1.  The attacker identifies a Heimdall instance with host-based access control rules.
2.  The attacker identifies a specific rule where the host is used for access control (e.g., `admin.example.com`).
3.  The attacker crafts an HTTP request with a `Host` header that differs only in casing (e.g., `Admin.Example.Com`).
4.  Heimdall fails to match the intended rule due to the case-sensitive comparison.
5.  If no default rule is configured, Heimdall returns a "404 Not Found" error.
6.  If a permissive default rule is configured (e.g., allowing anonymous access, which is discouraged since v0.16.0), Heimdall executes this default rule.
7.  The attacker gains unauthorized access to resources or functionality that should be protected by the intended rule.
8.  The attacker exploits the gained access to modify data, invoke functionality, or escalate privileges depending on the exposed functionality.

## Impact

Bypassing access control policies enforced by Heimdall can lead to unauthorized access to sensitive data, modification of critical information, or invocation of restricted functionality. Depending on the exposed functionality, this could also lead to privilege escalation. The severity of the impact depends heavily on the misconfiguration of Heimdall's rules, particularly the presence of overly permissive default rules. Successful exploitation can compromise the confidentiality, integrity, and availability of the protected application or service.

## Recommendation

*   Normalize request hosts to lowercase in layers in front of Heimdall to mitigate the case sensitivity issue.
*   Avoid configuring permissive default rules. Remove or disable the `--insecure` or `--insecure-skip-secure-default-rule-enforcement` flags.
*   When using the `regex` type for host matching, define expressions in a case-insensitive manner (e.g., `(?i)^admin\.example\.com$`).
*   Upgrade to Heimdall version 0.17.14 or later to patch the vulnerability directly.
