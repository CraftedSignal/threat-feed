---
title: AVideo HLS Path Traversal Vulnerability (CVE-2026-33292)
slug: 2024-01-avideo-path-traversal
description: AVideo versions before 26.0 are vulnerable to an unauthenticated path traversal attack via the HLS streaming endpoint, allowing unauthorized access to private or paid videos by manipulating the `videoDirectory` GET parameter due to inconsistent path handling.
date: "2024-01-24T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - avideo
  - path-traversal
  - cve-2026-33292
  - webserver
vendors:
  - WWBN
products:
  - AVideo
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33292
rules:
  - title: AVideo HLS Path Traversal Attempt
    description: Detects path traversal attempts in the AVideo HLS streaming endpoint by monitoring the videoDirectory parameter for '..' sequences.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: AVideo HLS Unauthorized Access Attempt
    description: Detects potential unauthorized access attempts to AVideo HLS endpoint based on HTTP status codes.
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

WWBN AVideo, an open-source video platform, is susceptible to a path traversal vulnerability in versions prior to 26.0. The vulnerability, identified as CVE-2026-33292, resides within the HLS streaming endpoint (`view/hls.php`). An unauthenticated attacker can exploit this flaw to bypass authorization checks and stream private or paid videos without proper credentials. The root cause lies in the inconsistent handling of the `videoDirectory` GET parameter, where authorization checks truncate the path while file access preserves traversal sequences ("../"), creating a split-oracle condition. Successful exploitation grants unauthorized access to restricted content, potentially leading to data leakage and financial losses for content creators and platform owners. The vulnerability was patched in version 26.0.

## Attack Chain

1. The attacker crafts a malicious HTTP GET request targeting the `view/hls.php` endpoint.
2. The request includes the `videoDirectory` parameter with a path traversal sequence (e.g., `../../private_video`).
3. The authorization check truncates the `videoDirectory` parameter at the first `/`, effectively validating against a different, potentially public, video.
4. The file access mechanism uses the original, untruncated `videoDirectory` parameter, resolving the path with traversal sequences.
5. The server retrieves the content from the specified private video file based on the manipulated path.
6. The server streams the content of the unauthorized video back to the attacker.
7. The attacker gains unauthorized access to private or paid video content.

## Impact

Successful exploitation of CVE-2026-33292 allows unauthenticated attackers to bypass access controls and stream private or paid videos on vulnerable AVideo platforms. This can lead to unauthorized access to sensitive content, financial losses for content creators who rely on paid subscriptions, and reputational damage for the platform. The number of affected AVideo installations is currently unknown, but any instance running a version prior to 26.0 is potentially vulnerable.

## Recommendation

*   Upgrade AVideo installations to version 26.0 or later to patch CVE-2026-33292.
*   Deploy the Sigma rule `AVideo HLS Path Traversal Attempt` to detect exploitation attempts against the vulnerable endpoint.
*   Monitor web server logs for suspicious requests to `view/hls.php` containing path traversal sequences in the `videoDirectory` parameter to identify potential attacks.
