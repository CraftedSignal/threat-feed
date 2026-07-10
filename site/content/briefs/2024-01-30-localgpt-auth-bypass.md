---
title: PromtEngineer localGPT Missing Authentication Vulnerability (CVE-2026-5000)
slug: 2024-01-30-localgpt-auth-bypass
description: A missing authentication vulnerability (CVE-2026-5000) exists in PromtEngineer localGPT's API Endpoint, allowing remote attackers to bypass authentication by manipulating the BaseHTTPRequestHandler argument, potentially leading to unauthorized access and data manipulation.
date: "2024-01-30T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - CVE-2026-5000
  - localGPT
  - authentication bypass
  - API vulnerability
vendors:
  - PromtEngineer
products:
  - localGPT
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5000
rules:
  - title: Detect Suspicious API Endpoint Access
    description: Detects suspicious access patterns to the API endpoint, potentially indicating an attempted authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect LocalGPT Authentication Bypass Attempt
    description: Detects attempts to bypass authentication in localGPT by manipulating request parameters.
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

A missing authentication vulnerability has been identified in PromtEngineer localGPT, specifically in versions up to commit 4d41c7d1713b16b216d8e062e51a5dd88b20b054. This flaw resides within the `LocalGPTHandler` function of the `backend/server.py` file, affecting the API Endpoint component. By manipulating the `BaseHTTPRequestHandler` argument, a remote attacker can bypass authentication mechanisms, gaining unauthorized access to the application's functionalities. Given the rolling release nature of localGPT, pinpointing specific vulnerable versions is challenging. Successful exploitation could grant attackers significant control over the localGPT instance, potentially leading to data breaches or system compromise. The vendor was notified but did not respond.

## Attack Chain

1. The attacker identifies a vulnerable localGPT instance running a version up to commit 4d41c7d1713b16b216d8e062e51a5dd88b20b054.
2. The attacker crafts a malicious HTTP request targeting the API Endpoint.
3. The crafted request manipulates the `BaseHTTPRequestHandler` argument.
4. The `LocalGPTHandler` function processes the manipulated request without proper authentication checks.
5. The attacker bypasses authentication and gains unauthorized access to the API Endpoint.
6. The attacker can now perform privileged actions, such as accessing sensitive data or modifying application settings.
7. The attacker could potentially exfiltrate data or inject malicious content.
8. The final objective is complete compromise of the localGPT instance, data theft, or disruption of services.

## Impact

Successful exploitation of CVE-2026-5000 allows unauthorized remote access to PromtEngineer localGPT instances. This could lead to the exposure of sensitive data processed by the application, modification of configurations, or injection of malicious content. The absence of versioning makes assessing the number of vulnerable installations difficult, but the impact on affected systems is significant, potentially resulting in data breaches, intellectual property theft, and reputational damage.

## Recommendation

*   Inspect web server logs for unusual requests to the `/api` endpoint that contain malformed or unexpected parameters in the request body, focusing on those affecting authentication or authorization processes. Use the "Detect Suspicious API Endpoint Access" Sigma rule below.
*   Monitor HTTP requests to the localGPT instance, specifically those targeting the API endpoint, for unusual manipulation of request headers or parameters, focusing on parameters related to authentication. Use the "Detect LocalGPT Authentication Bypass Attempt" Sigma rule.
*   While a patch is unavailable, implement rate limiting and input validation on the API endpoint to mitigate potential exploitation attempts based on abnormal traffic patterns.
