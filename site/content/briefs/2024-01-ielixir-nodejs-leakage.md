---
title: Ielixir-nodejs Cross-User Data Leakage Vulnerability
slug: 2024-01-ielixir-nodejs-leakage
description: The Ielixir-nodejs library before v3.1.4 is vulnerable to cross-user data leakage or information disclosure due to a race condition in the worker protocol, potentially exposing sensitive user data.
date: "2024-01-09T14:30:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cross-user data leakage
  - information disclosure
  - race condition
  - elixir-nodejs
vendors:
  - Revelry Labs
products:
  - Ielixir-nodejs
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
references:
  - https://github.com/advisories/GHSA-rwcr-rpcc-3g9m
  - https://github.com/revelrylabs/elixir-nodejs/issues/100
  - https://github.com/revelrylabs/elixir-nodejs/pull/105
rules:
  - title: Detect Suspicious Data Access Patterns in Application Logs
    description: Detects potential exploitation of the Ielixir-nodejs vulnerability by monitoring application logs for unusual data access patterns indicative of cross-user data leakage.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
  - title: Detect Error Status Codes Following Data Requests
    description: Detects potential exploitation of the Ielixir-nodejs vulnerability by monitoring for error status codes from user requests.
    platform: sigma
    severity: low
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Ielixir-nodejs library, versions prior to 3.1.4, contains a vulnerability that can lead to cross-user data leakage or information disclosure. This issue arises from a race condition in the worker protocol, where the lack of request-response correlation creates a "stale response" scenario. This means that in high-throughput environments, a worker may inadvertently return data intended for one user (User A) to another (User B). This is particularly concerning when the library handles sensitive user data, such as Personally Identifiable Information (PII), authentication tokens, or private records. The vulnerability was reported on March 26, 2026, and has been addressed in version 3.1.4 of the library. Exploitation of this vulnerability could lead to unauthorized access to sensitive information without triggering typical security alerts, making it difficult to detect.

## Attack Chain

1. An attacker identifies an application using a vulnerable version of Ielixir-nodejs (prior to v3.1.4).
2. The attacker initiates multiple requests to the application, specifically targeting endpoints that utilize the vulnerable library.
3. Under high load or timeout conditions, the worker process experiences a race condition due to the lack of proper request-response correlation.
4. The worker process retrieves data from a previous request (Data A, intended for User A) that is still present in the buffer.
5. The worker process incorrectly associates Data A with the attacker's current request (belonging to User B).
6. The application, unaware of the data mix-up, returns Data A to the attacker (User B).
7. The attacker gains unauthorized access to sensitive information intended for another user.
8. The attacker may use the leaked information for further malicious activities, such as account takeover or data exfiltration.

## Impact

Successful exploitation of this vulnerability can lead to the disclosure of sensitive user data, including PII, authentication tokens, and private records. The number of potential victims depends on the scope of applications utilizing the vulnerable Ielixir-nodejs library. This vulnerability poses a significant risk to organizations that handle sensitive user data, potentially leading to data breaches, compliance violations, and reputational damage. The vulnerability is difficult to trace because the application may not throw an error but instead provide "valid-looking" yet entirely incorrect and private data to the wrong session.

## Recommendation

*   Upgrade the Ielixir-nodejs library to version 3.1.4 or later to address the vulnerability as described in the advisory ([https://github.com/advisories/GHSA-rwcr-rpcc-3g9m](https://github.com/advisories/GHSA-rwcr-rpcc-3g9m)).
*   Implement robust input validation and output sanitization mechanisms in applications using Ielixir-nodejs to mitigate the impact of potential data leakage.
*   Monitor application logs for unusual data access patterns or unexpected data being returned to users; tune the provided Sigma rule to detect potential exploitation attempts.
*   Consider implementing request tracing and correlation mechanisms within the application to ensure proper request-response mapping and prevent stale responses.
