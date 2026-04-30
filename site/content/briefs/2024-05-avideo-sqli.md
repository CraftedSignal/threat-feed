---
title: WWBN AVideo SQL Injection Vulnerability (CVE-2026-33723)
slug: 2024-05-avideo-sqli
description: WWBN AVideo platform versions up to 26.0 are vulnerable to SQL injection (CVE-2026-33723), allowing authenticated attackers to inject arbitrary SQL commands via the 'user_id' POST parameter and extract sensitive data such as password hashes, API keys, and encryption salts.
date: "2026-03-23T19:16:42Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - avideo
  - sqli
  - cve-2026-33723
  - web-application
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33723
rules:
  - title: Detect AVideo Subscribe SQL Injection Attempt
    description: Detects potential SQL injection attempts in AVideo's subscribe endpoints by looking for common SQL keywords in the user_id parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect AVideo Subscribe Error Based SQL Injection
    description: Detects potential error based SQL injection attempts in AVideo's subscribe endpoints by looking for common error based SQL keywords in the user_id parameter.
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

WWBN AVideo, an open-source video platform, is susceptible to a critical SQL injection vulnerability (CVE-2026-33723) affecting versions up to and including 26.0. The vulnerability resides within the `Subscribe::save()` method located in `objects/subscribe.php`. The application directly concatenates the `$this->users_id` property into an INSERT SQL query without proper sanitization or parameterized binding. This property originates from the `$_POST['user_id']` parameter in both…
