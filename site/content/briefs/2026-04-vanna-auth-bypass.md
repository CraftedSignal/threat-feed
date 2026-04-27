---
title: vanna-ai vanna Authentication Bypass Vulnerability (CVE-2026-5320)
slug: 2026-04-vanna-auth-bypass
description: CVE-2026-5320 describes an unauthenticated remote access vulnerability in vanna-ai vanna up to version 2.0.2 via manipulation of the /api/vanna/v2/ Chat API endpoint, potentially allowing unauthorized access and actions.
date: "2026-04-02T05:16:04Z"
severities:
  - high
tags:
  - authentication-bypass
  - cve-2026-5320
  - vanna-ai
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-5320
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5320
  - https://github.com/August829/CVEP/issues/13
  - https://vuldb.com/submit/780727
  - https://vuldb.com/vuln/354652
  - https://vuldb.com/vuln/354652/cti
rules:
  - title: Detect vanna-ai vanna Authentication Bypass Attempt
    description: Detects potential exploitation attempts of CVE-2026-5320 by monitoring requests to the /api/vanna/v2/ endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect vanna-ai vanna Authentication Bypass - Error Response
    description: Detects potential exploitation attempts of CVE-2026-5320 based on abnormal server responses.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical authentication bypass vulnerability, identified as CVE-2026-5320, affects vanna-ai vanna versions up to 2.0.2. The vulnerability lies within the Chat API Endpoint located at `/api/vanna/v2/`. Successful exploitation allows remote attackers to bypass authentication mechanisms through a yet unspecified manipulation of the API endpoint. Public exploits are available, increasing the risk of widespread exploitation. The vendor has been unresponsive to disclosure attempts, further raising…
