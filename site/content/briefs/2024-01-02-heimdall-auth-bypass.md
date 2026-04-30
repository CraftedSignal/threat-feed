---
title: Heimdall Authorization Bypass via Path Normalization Mismatch
slug: 2024-01-02-heimdall-auth-bypass
description: Heimdall is vulnerable to an authorization bypass due to a path normalization mismatch between Heimdall and downstream components, potentially leading to unauthorized access and privilege escalation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - path-normalization
  - cloud
vendors:
  - dadrus
products:
  - heimdall
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-3q34-rx83-r6mq
rules:
  - title: Detect HTTP Requests with Dot-Segments
    description: Detects HTTP requests containing dot-segments (..) in the URI, which may indicate path traversal attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect URL Encoded Dot-Segments in HTTP Requests
    description: Detects HTTP requests containing URL-encoded dot-segments (%2e%2e) in the URI, which may indicate path traversal attempts.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Heimdall, a cloud-native security proxy, is susceptible to an authorization bypass vulnerability. This issue arises from a discrepancy in how Heimdall handles request paths compared to downstream components. Specifically, Heimdall performs rule matching on the raw, non-normalized request path, while downstream components might normalize dot-segments (e.g., `/user/../admin`) according to RFC 3986. This can lead to Heimdall authorizing a request based on the raw path, whereas the downstream service processes a different, normalized path, potentially bypassing intended access controls. The vulnerability affects Heimdall versions prior to 0.17.14. Exploitation is possible when using wildcards in rule matching without further constraints. This could allow attackers to access restricted resources or functionalities.

## Attack Chain

1.  Attacker crafts a malicious HTTP request with a path containing dot-segments (e.g., `/public/../user/resource`).
2.  The request is sent to the Heimdall proxy.
3.  Heimdall performs rule matching on the raw, non-normalized path (`/public/../user/resource`).
4.  Heimdall incorrectly matches the request to a less restrictive rule, such as a rule for `/public/**`, due to the initial `/public` segment.
5.  Heimdall authorizes the request based on the matched rule, potentially allowing anonymous access.
6.  The request is forwarded to the downstream service.
7.  The downstream service normalizes the request path to `/user/resource`.
8.  The downstream service processes the request as `/user/resource`, bypassing the intended access controls for that resource, possibly leading to data access or privilege escalation.

## Impact

Successful exploitation of this vulnerability allows attackers to bypass access control policies enforced by Heimdall. This can lead to unauthorized access to sensitive data, modification of restricted data, invocation of privileged functionality without proper authentication or authorization, and in certain configurations, escalation of privileges. The number of potential victims depends on the deployment and configuration of Heimdall within affected environments.

## Recommendation

*   Apply the available patch to upgrade Heimdall to version 0.17.14 or later to remediate the vulnerability.
*   Implement HTTP path normalization or rejection of HTTP paths containing relative path expressions in layers in front of Heimdall, as suggested in the advisory.
*   Deploy the Sigma rule provided below to detect suspicious HTTP requests containing dot-segments (..) in the request path.
*   Configure your proxies (e.g., Envoy) to normalize paths, as described in the advisory.
