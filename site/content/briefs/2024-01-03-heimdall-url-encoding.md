---
title: Heimdall Authorization Bypass via Case-Sensitive URL-Encoded Slash Handling
slug: 2024-01-03-heimdall-url-encoding
description: Heimdall versions before 0.17.14 are vulnerable to inconsistent path interpretation due to case-sensitive handling of URL-encoded slashes; when `allow_encoded_slashes` is set to `off` (the default), the lowercase `%2f` is not recognized, potentially leading to authorization bypass if the default rule is overly permissive and the upstream service interprets `%2f` as a path separator.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - heimdall
  - authorization-bypass
  - url-encoding
vendors:
  - dadrus
products:
  - Heimdall (versions prior to 0.17.14)
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-43jv-5j4x-qv67
rules:
  - title: Detect HTTP Requests with Lowercase URL-Encoded Slash to Heimdall
    description: Detects HTTP requests containing lowercase URL-encoded slashes (%2f) in the URI, potentially indicating an attempt to exploit the Heimdall authorization bypass vulnerability.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Heimdall Startup with Insecure Flags
    description: Detects Heimdall instances started with the `--insecure` or `--insecure-skip-secure-default-rule-enforcement` flags, which weakens security posture.
    platform: sigma
    severity: medium
    tactics:
      - configuration
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Heimdall, a cloud-native access management proxy, is susceptible to an authorization bypass vulnerability due to its case-sensitive handling of URL-encoded slashes. Specifically, versions prior to 0.17.14 fail to properly process lowercase URL-encoded forward slashes (`%2f`) when the `allow_encoded_slashes` option is disabled, which is the default configuration. This discrepancy arises because, while percent-encoding should be case-insensitive, Heimdall only recognizes the uppercase `%2F`. This inconsistency can be exploited if an attacker crafts requests with lowercase encoded slashes that Heimdall doesn't normalize, while upstream services do. This can result in the application of an unintended default rule (if configured permissively), leading to unauthorized access to protected resources. The vulnerability is mitigated by ensuring secure default configurations or proper input validation.

## Attack Chain

1. The attacker identifies a Heimdall instance enforcing access control policies.
2. The attacker crafts a malicious HTTP request targeting a protected resource, such as `/admin/secret`.
3. The attacker replaces the forward slash in the request path with a lowercase URL-encoded slash (`%2f`), resulting in a request like `/admin%2fsecret`.
4. The request reaches the Heimdall instance. Due to the case-sensitive handling of URL-encoded slashes, Heimdall does not normalize the `%2f`.
5. Heimdall fails to match the request to the intended access control rule (e.g., a rule matching `/admin/**`).
6. Heimdall executes the default rule, which, if misconfigured to be overly permissive (allowing anonymous access), grants access.
7. The request is forwarded to the upstream service.
8. The upstream service interprets `%2f` as a forward slash, effectively processing the request as `/admin/secret`, granting the attacker unauthorized access to the protected resource.

## Impact

Successful exploitation of this vulnerability allows an attacker to bypass intended access control policies, potentially leading to unauthorized access to sensitive data, modification of restricted resources, or invocation of privileged functionality. Depending on the exposed functionality and the configuration of the upstream service, this could also lead to privilege escalation. The number of victims and sectors targeted depend heavily on the deployment and configuration of Heimdall instances.

## Recommendation

*   Upgrade to Heimdall version 0.17.14 or later to address the case-sensitive handling of URL-encoded slashes.
*   Avoid using the `--insecure` or `--insecure-skip-secure-default-rule-enforcement` flags during Heimdall configuration, as these flags weaken security posture.
*   Configure the default rule in Heimdall to implement a "deny by default" policy to minimize the risk of unintended access.
*   Implement input validation at layers in front of Heimdall (e.g., in proxies like Traefik) to reject HTTP paths containing encoded slashes, providing an additional layer of defense.
*   If using JWTs, include the ID of the rule expected to be executed and verify that value in the project's service.
