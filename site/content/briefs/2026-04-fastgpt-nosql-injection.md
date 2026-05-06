---
title: FastGPT NoSQL Injection Vulnerability (CVE-2026-40351)
slug: 2026-04-fastgpt-nosql-injection
description: FastGPT versions before 4.14.9.5 are vulnerable to NoSQL injection, allowing unauthenticated attackers to bypass authentication and gain administrative access.
date: "2026-04-18T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - NoSQL injection
  - authentication bypass
  - CVE-2026-40351
  - FastGPT
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-40351
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40351
  - https://github.com/labring/FastGPT/commit/bd966d479fbe414d02679cf79f9eaaab3d100a2d
  - https://github.com/labring/FastGPT/releases/tag/v4.14.9.5
  - https://github.com/labring/FastGPT/security/advisories/GHSA-x8mx-2mr7-h9xg
rules:
  - title: Detect FastGPT NoSQL Injection Attempt
    description: Detects attempts to exploit the NoSQL injection vulnerability in FastGPT by searching for MongoDB query operators in POST requests to the login endpoint.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect FastGPT Version Pre 4.14.9.5 in User Agent
    description: Detects connections to FastGPT with a User-Agent string indicating a version prior to the patched version.
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

FastGPT is an AI Agent building platform. Versions prior to 4.14.9.5 are susceptible to a critical NoSQL injection vulnerability (CVE-2026-40351) affecting the password-based login endpoint. The vulnerability stems from the use of TypeScript type assertion without runtime validation, enabling unauthenticated attackers to inject MongoDB query operators within the password field. This bypasses the intended password check, granting the attacker the ability to authenticate as any user, including the root administrator. Successful exploitation leads to complete control over the FastGPT instance and its associated data. This vulnerability was addressed in FastGPT version 4.14.9.5. All users of FastGPT versions prior to 4.14.9.5 are vulnerable to this attack.

## Attack Chain

1.  An unauthenticated attacker identifies a vulnerable FastGPT instance running a version prior to 4.14.9.5.
2.  The attacker crafts a malicious HTTP POST request to the password-based login endpoint.
3.  Within the POST request body, the attacker places a MongoDB query operator object (e.g., `{"$ne": ""}`) in the password field, bypassing the standard password check.
4.  The vulnerable FastGPT application processes the malicious request without proper validation.
5.  The MongoDB query operator is executed, bypassing the authentication mechanism.
6.  The attacker is granted unauthorized access to the FastGPT application, assuming the identity of an arbitrary user, including the root administrator.
7.  The attacker leverages their administrative privileges to access sensitive data, modify configurations, or perform other malicious actions within the FastGPT instance.

## Impact

Successful exploitation of CVE-2026-40351 allows an unauthenticated attacker to gain complete control over a FastGPT instance. This can lead to unauthorized access to sensitive AI agent configurations, user data, and other critical information. The impact includes data breaches, service disruption, and potential compromise of downstream systems that rely on the FastGPT platform. Given the critical nature of AI agent building platforms, the compromise of a FastGPT instance can have far-reaching consequences.

## Recommendation

*   Immediately upgrade all FastGPT instances to version 4.14.9.5 or later to patch CVE-2026-40351.
*   Deploy the Sigma rule `Detect FastGPT NoSQL Injection Attempt` to identify potential exploitation attempts targeting the login endpoint.
*   Monitor web server logs for unusual POST requests to the login endpoint, specifically looking for MongoDB query operators within the password field as detected by rule `Detect FastGPT NoSQL Injection Attempt`.
*   Review and restrict network access to the FastGPT instance to only authorized users and systems to minimize the attack surface.
