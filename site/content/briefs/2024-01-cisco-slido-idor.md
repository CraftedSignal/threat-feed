---
title: Cisco Slido Insecure Direct Object Reference Vulnerability
slug: 2024-01-cisco-slido-idor
description: An insecure direct object reference in Cisco Slido's REST API could have allowed an authenticated remote attacker to access social profile data or affect quiz/poll results.
date: "2026-05-06T16:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - idor
  - cisco
  - slido
  - credential-access
vendors:
  - Cisco
products:
  - Slido
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-slido-idor-CpsFmKxN
rules:
  - title: Detect Suspicious Slido API Access
    description: Detects potential exploitation attempts of Slido API by monitoring HTTP status codes and URI patterns.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - webserver
      - linux
  - title: Detect Potential Slido Quiz Manipulation
    description: Detects potential manipulation of quiz/poll results in Slido based on URI and method.
    platform: sigma
    severity: low
    tactics:
      - integrity_impact
    techniques:
      - T1565.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability in the REST API of Cisco Slido, a web-based audience interaction platform, could have been exploited by an authenticated, remote attacker. The vulnerability stems from an insecure direct object reference (IDOR). An attacker could potentially leverage this vulnerability to access sensitive social profile data of other users within the Slido platform or manipulate quiz and poll results. Cisco has addressed this vulnerability in their Slido service; no specific version numbers are mentioned in the advisory. The scope of the targeting is all users of the Slido platform.

## Attack Chain

1.  Attacker authenticates to the Cisco Slido platform using valid credentials.
2.  Attacker identifies a vulnerable REST API endpoint related to user profile data or quiz/poll results.
3.  Attacker crafts a malicious request to the API endpoint, manipulating the object reference (e.g., user ID or poll ID) to target another user's profile or a specific poll.
4.  The crafted request is sent to the Cisco Slido server.
5.  Due to the IDOR vulnerability, the server processes the request without proper authorization checks, granting access to the targeted user's social profile data or allowing modification of quiz/poll results.
6.  Attacker views the retrieved social profile data of the targeted user, potentially including sensitive information.
7.  Alternatively, the attacker successfully alters the quiz/poll results, skewing outcomes or manipulating participation data.
8.  The attacker continues to exploit the vulnerability to gather more user data or further manipulate quiz/poll results, impacting the integrity of the Slido platform.

## Impact

Successful exploitation of this vulnerability could have resulted in unauthorized access to sensitive user data, including social profiles. An attacker could potentially harvest personal information or use the compromised profiles for malicious purposes. Furthermore, the manipulation of quiz and poll results could undermine the integrity of these interactive elements, leading to skewed outcomes and a loss of trust in the platform. The number of affected users and the full extent of potential damage is unknown.

## Recommendation

*   While Cisco states that they have addressed this vulnerability and that no customer action is required, monitor web server logs for unusual activity targeting API endpoints related to user profile data or quiz/poll interactions.
*   Implement the provided Sigma rule `Detect Suspicious Slido API Access` to identify potential exploitation attempts based on HTTP status codes and URI patterns.
*   Monitor for unexpected modifications to user profiles or quiz/poll results within the Slido platform's administrative interface.
