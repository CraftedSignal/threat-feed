---
title: Luanti 5 Improper Access Control Vulnerability (CVE-2026-40960)
slug: 2026-04-luanti-access
description: Luanti 5 before 5.15.2 allows unintended access to an insecure environment if a crafted mod intercepts requests when secure mods are enabled, potentially leading to unauthorized access and control.
date: "2026-04-16T01:16:11Z"
severities:
  - high
tags:
  - cve-2026-40960
  - luanti
  - access-control
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40960
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40960
  - https://github.com/luanti-org/luanti/commit/0faf529bc4b89e70a275ed1162047815118f2413
  - https://github.com/luanti-org/luanti/commit/827fd4cf7f989482b2dad381fa4afd642ea73e8c
  - https://github.com/luanti-org/luanti/security/advisories/GHSA-22c4-238c-m5j4
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious HTTP Requests from Unusual Luanti Mods
    description: Detects potentially malicious HTTP requests originating from uncommon or newly deployed Luanti mods
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Luanti Mod Deployment
    description: Detects deployment of new Luanti modules, which should be monitored for suspicious activity related to CVE-2026-40960
    platform: sigma
    severity: informational
    tactics:
      - persistence
    techniques:
      - T1105
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Luanti 5, a software package (details not provided in source), prior to version 5.15.2, suffers from an improper access control vulnerability (CVE-2026-40960). This flaw can be exploited when at least one mod is configured as either `secure.trusted_mods` or `secure.http_mods`. Under these conditions, a specially crafted malicious mod can intercept requests intended for the insecure environment or HTTP API, effectively bypassing intended security controls. The vulnerability allows the malicious…
