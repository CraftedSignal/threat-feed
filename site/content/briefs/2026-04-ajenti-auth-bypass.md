---
title: Ajenti Authorization Bypass Vulnerability (CVE-2026-35175)
slug: 2026-04-ajenti-auth-bypass
description: Ajenti versions before 2.2.15 contain an authorization bypass vulnerability that allows authenticated non-superuser users to install custom packages, potentially leading to privilege escalation and system compromise.
date: "2026-04-03T03:57:43Z"
severities:
  - high
tags:
  - ajenti
  - authorization-bypass
  - privilege-escalation
  - CVE-2026-35175
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-73jv-44c3-j5p2
  - https://github.com/ajenti/ajenti/releases/tag/v2.2.15
rules:
  - title: Detect Suspicious Ajenti Package Installation
    description: Detects potential exploitation of Ajenti authorization bypass vulnerability through monitoring of custom package installations.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Unauthorized Package Installation via Auth Bypass
    description: Detects unauthorized package installations in Ajenti, indicative of a potential auth bypass. This will need tuning to account for authorized users who can install packages.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Ajenti is a web-based system administration panel. Prior to version 2.2.15, a flaw exists in the `auth_users` authentication plugin that permits authenticated users lacking superuser privileges to install custom packages. This vulnerability, identified as CVE-2026-35175, allows a low-privileged user to bypass intended authorization checks, potentially escalating their privileges and compromising the entire system. An attacker could leverage this vulnerability to install malicious packages…
