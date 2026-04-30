---
title: MacCMS 2025.1000.4052 Missing Authentication Vulnerability (CVE-2026-4562)
slug: 2026-03-maccms-auth-bypass
description: A missing authentication vulnerability exists in MacCMS 2025.1000.4052, specifically affecting the Timming API Endpoint component in application/api/controller/Timming.php, allowing remote attackers to bypass authentication.
date: "2026-03-24T12:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - CVE-2026-4562
  - authentication-bypass
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4562
  - https://github.com/HuajiHD/CVE/issues/9
  - https://vuldb.com/?ctiid.352399
  - https://vuldb.com/?id.352399
  - https://vuldb.com/?submit.775039
rules:
  - title: Detect Access to MacCMS Timming API Endpoint
    description: Detects access to the Timming API endpoint in MacCMS, which is vulnerable to authentication bypass.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect POST Requests to MacCMS Timming API Endpoint
    description: Detects POST requests to the Timming API endpoint, potentially indicating an exploit attempt.
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

CVE-2026-4562 details a missing authentication vulnerability within MacCMS version 2025.1000.4052. The vulnerability is located in the `application/api/controller/Timming.php` file, specifically within the Timming API Endpoint component. This flaw allows unauthenticated remote attackers to execute actions that should normally require authentication. The vulnerability has been publicly disclosed, increasing the risk of exploitation. Defenders should prioritize identifying and mitigating…
