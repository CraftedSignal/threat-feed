---
title: Monetr Lunch Flow SSRF Vulnerability
slug: 2024-05-monetr-ssrf
description: A server-side request forgery (SSRF) vulnerability in Monetr's Lunch Flow integration allows authenticated users on self-hosted instances to send HTTP GET requests to arbitrary URLs, potentially exposing sensitive information.
date: "2024-05-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ssrf
  - monitr
  - github-advisory
vendors:
  - Monetr
products:
  - Monetr
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-29v9-frvh-c426
iocs:
  - type: url
    value: https://lunchflow.app/api/v1
ioc_counts:
  url: 1
rules:
  - title: Detect Monetr Lunch Flow Link Creation with Suspicious URL
    description: Detects attempts to create Lunch Flow links with URLs pointing to private IP addresses or cloud metadata endpoints, indicative of SSRF attempts.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Monetr Warning Log for Rejected Lunch Flow API URL
    description: Detects warning logs indicating that a Lunch Flow API URL was rejected because it's not in the configured allowlist.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A server-side request forgery (SSRF) vulnerability was identified in the Lunch Flow integration of Monetr, affecting self-hosted instances. This vulnerability allows any authenticated user to cause the Monetr server to issue HTTP GET requests to arbitrary URLs, with the response body from non-200 upstream responses reflected back in the API error message. The URL validator on the `POST /api/lunch_flow/link` endpoint lacked sufficient filtering, failing to block loopback, RFC1918, link-local, or cloud-provider metadata addresses. This allows attackers to potentially access internal resources or cloud instance metadata. The vulnerability was addressed in Monetr version 1.12.5. The hosted `my.monetr.app` service is not affected because `LunchFlow.Enabled` is set to `false`.

## Attack Chain

1. An attacker registers an account on a vulnerable self-hosted Monetr instance where public sign-up is enabled (`AllowSignUp=true`).
2. The attacker authenticates to the Monetr instance.
3. The attacker crafts a malicious `POST` request to the `/api/lunch_flow/link` endpoint, providing a URL pointing to an internal resource, such as a cloud metadata endpoint (e.g., `http://169.254.169.254/latest/meta-data/`).
4. The Monetr server, due to insufficient URL validation, accepts the malicious URL.
5. The Monetr server issues an HTTP GET request to the attacker-supplied URL.
6. The external service or internal resource responds to the Monetr server.
7. If the response is not a 200 OK, the Monetr server reflects the response body in the API error message within the JSON response to the attacker.
8. The attacker observes the reflected response body, potentially revealing sensitive information like cloud instance metadata or internal service details.

## Impact

Successful exploitation of this SSRF vulnerability can lead to the exposure of sensitive information, such as cloud instance metadata (e.g., AWS EC2 IMDS). This could allow an attacker to gain unauthorized access to other cloud resources or internal systems. The vulnerable instances are self-hosted Monetr deployments running the default configuration with `LunchFlow.Enabled=true` and `AllowSignUp=true`. An attacker could also cause a denial-of-service by providing a URL that returns a very large response body, exhausting the server's memory.

## Recommendation

*   Upgrade to Monetr version `v1.12.5` or later to patch the SSRF vulnerability. This version introduces a new config field `LunchFlow.AllowedApiUrls` and caps response body reads at 10 MiB.
*   For operators who cannot upgrade immediately, set `MONETR_ALLOW_SIGN_UP=false` to disable public sign-up, limiting access to the vulnerable endpoint to trusted users.
*   Alternatively, disable Lunch Flow entirely by setting `lunchFlow.enabled: false` in your config file. This will cause the vulnerable endpoints to return 404.
*   Implement network-level egress restrictions to limit outbound HTTP traffic from the Monetr pod/container to only `lunchflow.app` (or other legitimate Lunch Flow hosts), mitigating the SSRF primitive.
