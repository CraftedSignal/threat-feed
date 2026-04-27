---
title: Census CSWeb 8.0.1 Configuration File Disclosure Vulnerability
slug: 2026-03-census-csweb-config-disclosure
description: Census CSWeb 8.0.1 is vulnerable to unauthenticated remote configuration file disclosure via HTTP requests to the `/app/config` path, potentially exposing sensitive secrets; fixed in 8.1.0 alpha.
date: "2026-03-24T14:00:00Z"
severities:
  - critical
tags:
  - cve-2025-60949
  - information-disclosure
  - webserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-60949
  - https://github.com/csprousers/csweb/commit/eba0b59a243390a1a4f9524cce6dbc0314bf0d91
  - https://github.com/hx381/cspro-exploits
  - https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/2026/va-26-082-01.json
rules:
  - title: Detect Unauthenticated Access to Configuration Files
    description: Detects unauthenticated HTTP GET requests to the /app/config directory, indicative of potential CVE-2025-60949 exploitation.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Multiple Failed Accesses to Configuration Files
    description: Detects a high number of failed access attempts to the /app/config directory from a single source IP, possibly indicating an automated exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Census CSWeb version 8.0.1 is susceptible to a critical vulnerability (CVE-2025-60949) that allows unauthenticated remote attackers to access sensitive configuration files. This exposure occurs because the `/app/config` directory is reachable via HTTP in certain deployments. By sending a specially crafted request to this path, an attacker can potentially obtain sensitive information, such as API keys, database credentials, and other secrets stored within the configuration files. This…
