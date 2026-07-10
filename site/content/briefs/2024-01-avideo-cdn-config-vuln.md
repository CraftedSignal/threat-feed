---
title: AVideo CDN Plugin Unauthenticated Configuration Modification
slug: 2024-01-avideo-cdn-config-vuln
description: AVideo is vulnerable to unauthenticated configuration modification in its CDN plugin due to a bypassed key validation check when the default empty key is used, allowing modification of CDN URLs, storage credentials, and the authentication key itself.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - avideo
  - cdn
  - configuration-modification
  - vulnerability
vendors:
  - AVideo
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: Application Software Configuration
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33719
rules:
  - title: AVideo CDN Configuration Modification Attempt
    description: Detects attempts to modify AVideo CDN configuration by sending POST requests to vulnerable endpoints without authentication.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - webserver
      - linux
  - title: AVideo CDN Configuration Access via GET Request
    description: Detects GET requests to AVideo CDN status endpoint without authentication.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

AVideo, an open source video platform, contains a critical vulnerability (CVE-2026-33719) within its CDN plugin. Versions up to and including 26.0 are affected. The vulnerability stems from the endpoints `plugin/CDN/status.json.php` and `plugin/CDN/disable.json.php` using key-based authentication with an empty string as the default key. Critically, when the CDN plugin is enabled but the key remains at its default (empty) state, the authentication check is bypassed entirely. This allows any unauthenticated attacker to fully modify the CDN configuration through mass-assignment via the `par` request parameter. This includes the ability to manipulate CDN URLs, storage credentials, and even the authentication key itself. A patch has been released in commit adeff0a31ba04a56f411eef256139fd7ed7d4310. This is significant because it can lead to complete compromise of the video delivery infrastructure.

## Attack Chain

1. An attacker identifies an AVideo instance with the CDN plugin enabled.
2. The attacker checks the CDN configuration by sending a GET request to `plugin/CDN/status.json.php` without any authentication headers to confirm if CDN plugin is enabled and running with default configuration.
3. If the CDN key is the default empty string, the attacker crafts a malicious POST request to `plugin/CDN/status.json.php` or `plugin/CDN/disable.json.php`.
4. The POST request includes the `par` parameter containing a JSON object with modified CDN settings, such as CDN URLs and storage credentials.
5. Due to the bypassed authentication, the AVideo server processes the request and updates the CDN configuration.
6. The attacker can modify the CDN URL to point to a malicious server hosting malware or phishing content.
7. Legitimate users requesting video content are redirected to the attacker's malicious CDN.
8. The attacker can also steal storage credentials and compromise the CDN's data.

## Impact

Successful exploitation of CVE-2026-33719 allows an unauthenticated attacker to take complete control over the video delivery infrastructure. This can result in serving malicious content to users, data exfiltration from the CDN storage, or complete disruption of video services. The number of victims depends on the popularity of the affected AVideo instances. This vulnerability impacts any organization using AVideo with the CDN plugin enabled and the default configuration, including educational institutions, media companies, and content creators.

## Recommendation

*   Apply the patch from commit adeff0a31ba04a56f411eef256139fd7ed7d4310 or upgrade to a version of AVideo that includes this fix to remediate CVE-2026-33719.
*   Deploy the Sigma rules provided in this brief to your SIEM to detect potential exploitation attempts targeting the `plugin/CDN/status.json.php` and `plugin/CDN/disable.json.php` endpoints.
*   Monitor web server logs for POST requests to `plugin/CDN/status.json.php` or `plugin/CDN/disable.json.php` endpoints without proper authentication headers, as these may indicate an attempted exploit.
*   As a temporary workaround, configure a strong, non-default key for the CDN plugin to prevent the authentication bypass.
