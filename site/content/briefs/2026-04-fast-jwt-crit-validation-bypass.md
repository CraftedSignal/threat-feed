---
title: fast-jwt Library Vulnerability Allows crit Header Validation Bypass
slug: 2026-04-fast-jwt-crit-validation-bypass
description: The fast-jwt library fails to validate the 'crit' header, allowing attackers to bypass security policies and potentially achieve split-brain verification in mixed-library environments.
date: "2026-04-03T22:01:25Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - jwt
  - vulnerability
  - authentication
  - authorization
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2025-59420
    cvss: 7.5
    epss: 0.00012
references:
  - https://github.com/advisories/GHSA-hm7r-c7qw-ghp6
rules:
  - title: Detect fast-jwt crit Header Bypass Attempt
    description: Detects JWTs with unsupported critical extensions that may bypass intended security policies in applications using vulnerable versions of fast-jwt.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
  - title: Detect JWT with custom header x-custom-policy
    description: Detects JWTs that contains custom header x-custom-policy.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1553.005
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The `fast-jwt` library, versions 6.1.0 and below, exhibits a critical vulnerability where it does not properly validate the `crit` (Critical) Header Parameter as defined in RFC 7515. This oversight allows JWS tokens containing unrecognized extensions within the `crit` array to be accepted instead of being rejected as mandated by the RFC. The vulnerability, identified as CVE-2026-35042, can lead to significant security implications, especially in environments utilizing a mix of JWT verification libraries. This flaw enables attackers to potentially bypass security policies and token binding protections, creating a window for unauthorized access or actions.

## Attack Chain

1.  The attacker crafts a JWT with a `crit` header containing an extension (e.g., "x-custom-policy") that `fast-jwt` does not support.
2.  The attacker includes this unsupported extension header (e.g., `"x-custom-policy": "require-mfa"`) in the JWT header.
3.  The attacker signs the JWT using a valid signing key and algorithm (e.g., HS256).
4.  The attacker presents the crafted JWT to a system or application using the vulnerable `fast-jwt` library for verification.
5.  The `fast-jwt` library incorrectly accepts the token without validating the `crit` header extensions.
6.  The application logic proceeds based on the accepted (but invalid) JWT, potentially granting unauthorized access or privileges.
7.  If other JWT libraries are used in the same environment that *do* properly validate the `crit` header, a "split-brain" verification scenario can occur, with some systems rejecting the token while others accept it.
8.  The ultimate objective is to bypass intended security policies, such as multi-factor authentication or token binding requirements, gaining unauthorized access or control.

## Impact

Successful exploitation of this vulnerability (CVE-2026-35042) can lead to several critical consequences. First, in mixed-library environments, it creates a split-brain verification scenario where different systems interpret the same token differently. Second, it allows attackers to bypass security policies enforced through the `crit` header, such as mandatory multi-factor authentication. Finally, it can circumvent token binding mechanisms (RFC 7800 `cnf` confirmation), weakening overall authentication security. The full impact analysis is described in CVE-2025-59420. This vulnerability affects applications using `fast-jwt` version 6.1.0 and earlier.

## Recommendation

*   Upgrade the `fast-jwt` library to a version greater than 6.1.0 to remediate CVE-2026-35042.
*   Deploy the Sigma rule "Detect fast-jwt crit Header Bypass Attempt" to identify attempts to exploit this vulnerability in your environment.
*   If a mixed-library JWT verification environment exists, evaluate and standardize on a single JWT library that correctly handles the `crit` header parameter.
*   Review existing JWT usage to identify instances where the `crit` header is used for security policy enforcement and ensure that appropriate validation is in place.
