---
title: OpenViking Authentication Bypass Vulnerability (CVE-2026-40525)
slug: 2024-02-openviking-auth-bypass
description: OpenViking versions prior to commit c7bb167 are vulnerable to an authentication bypass that allows remote attackers to invoke privileged bot-control functionality without authentication when the api_key configuration is unset or empty, potentially leading to unauthorized access to downstream systems and data.
date: "2026-04-17T19:16:39Z"
severities:
  - critical
tags:
  - CVE-2026-40525
  - authentication-bypass
  - openviking
  - api
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40525
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40525
rules:
  - title: OpenViking Authentication Bypass Attempt
    description: Detects unauthorized requests to the VikingBot API endpoint without the X-API-Key header, indicating a potential authentication bypass attempt (CVE-2026-40525).
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: OpenViking API requests without API Key
    description: Detects requests to API endpoints associated with OpenViking that are missing the expected API key header.
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

OpenViking, a bot management framework, contains a critical authentication bypass vulnerability (CVE-2026-40525) affecting versions prior to commit c7bb167. Specifically, the VikingBot OpenAPI HTTP route surface fails to enforce authentication when the `api_key` configuration value is either unset or configured as an empty string. This vulnerability enables remote attackers with network access to the exposed OpenViking service to bypass authentication controls and execute privileged bot-control…
