---
title: fast-jwt Library Vulnerability Allows crit Header Validation Bypass
slug: 2026-04-fast-jwt-crit-validation-bypass
description: The fast-jwt library fails to validate the 'crit' header, allowing attackers to bypass security policies and potentially achieve split-brain verification in mixed-library environments.
date: "2026-04-03T22:01:25Z"
severities:
  - high
tags:
  - jwt
  - vulnerability
  - authentication
  - authorization
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2025-59420
    cvss: 7.5
    epss: 0.00012
references:
  - https://github.com/advisories/GHSA-hm7r-c7qw-ghp6
rules:
  - title: Detect fast-jwt crit Header Bypass Attempt
    description: Detects JWTs with unsupported critical extensions that may bypass intended security policies in applications using vulnerable versions of fast-jwt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
  - title: Detect JWT with custom header x-custom-policy
    description: Detects JWTs that contains custom header x-custom-policy.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `fast-jwt` library, versions 6.1.0 and below, exhibits a critical vulnerability where it does not properly validate the `crit` (Critical) Header Parameter as defined in RFC 7515. This oversight allows JWS tokens containing unrecognized extensions within the `crit` array to be accepted instead of being rejected as mandated by the RFC. The vulnerability, identified as CVE-2026-35042, can lead to significant security implications, especially in environments utilizing a mix of JWT verification…
