---
title: S3-Proxy Authentication Bypass via Percent-Encoded Slashes
slug: 2024-01-03-s3-proxy-auth-bypass
description: S3-Proxy is vulnerable to an authentication bypass due to inconsistent handling of percent-encoded slashes between the authentication middleware and bucket handler, allowing unauthorized access to protected resources.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - s3-proxy
  - authentication-bypass
  - url-encoding
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-rfgq-wgg8-662p
rules:
  - title: S3-Proxy Percent Encoded Slash in URI
    description: Detects requests to S3-Proxy containing a percent-encoded slash (%2F) in the URI, which may indicate an attempted authentication bypass.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: S3-Proxy Wildcard Character Matching Multiple Path Segments
    description: Detects requests to S3-Proxy where the wildcard character (*) matches multiple path segments, potentially indicating an attempt to bypass authentication by exploiting path traversal.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

S3-Proxy is vulnerable to an authentication bypass due to differing interpretations of URL paths. The auth middleware uses the encoded path (`r.URL.RequestURI()`), while the bucket handler uses the decoded path (`r.URL.Path`). This discrepancy allows attackers to craft requests containing percent-encoded slashes (`%2F`) to bypass authentication checks. Specifically, the `*` wildcard in resource paths, when used without a separator, matches across forward slashes, further exacerbating the issue. This can lead to unauthorized modification or deletion of objects in protected namespaces. Successful exploitation requires a vulnerable S3-Proxy configuration and allows attackers to bypass intended access controls. The issue was reported on 2026-05-05.

## Attack Chain

1.  Attacker identifies an S3-Proxy instance with vulnerable resource path configurations.
2.  The attacker crafts a PUT request with a URL containing a percent-encoded slash (`%2F`) within a path segment, such as `/upload/foo%2Frestricted/drafts/`.
3.  The request is received by the S3-Proxy server.
4.  The auth middleware uses `r.URL.RequestURI()` and matches the path against configured resource paths. Due to the encoded slash, the wildcard `*` matches the entire segment `foo%2Frestricted`.
5.  The bucket handler uses `r.URL.Path`, which decodes the `%2F` into a `/`, resulting in the path `/upload/foo/restricted/drafts/`.
6.  The request bypasses authentication because the auth middleware incorrectly matched an open route due to the encoded path.
7.  The bucket handler constructs an S3 key based on the decoded path, leading to the object being written to the protected `restricted` namespace without proper authentication.
8.  The attacker successfully writes an object to the protected namespace without credentials.

## Impact

Successful exploitation allows unauthorized users to bypass authentication controls and access protected resources within the S3-Proxy environment. This can result in unauthorized data modification, deletion, or exfiltration. The impact is significant as it undermines the intended access control mechanisms, potentially leading to data breaches or service disruption. The number of affected installations is unknown.

## Recommendation

*   Apply the fix by setting the separator argument to `'/'` in `glob.Compile` to prevent the wildcard `*` from matching across path segments as described in Issue 1.
*   Implement Option B, using `r.URL.EscapedPath()` in the bucket handler to ensure consistent handling of encoded paths and prevent namespace pollution as outlined in Issue 2.
*   Deploy the Sigma rule "S3-Proxy Percent Encoded Slash in URI" to detect requests containing `%2F` in the URI, which may indicate exploitation attempts.
*   Review and update all resource path definitions to ensure they correctly reflect the intended access controls after applying the fixes, as the fixes represent a breaking change in path interpretation.
*   Enable webserver logging to capture the full URI path (including encoded characters) for analysis and detection, to facilitate effective monitoring using the Sigma rules provided.
