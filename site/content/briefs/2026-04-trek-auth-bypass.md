---
title: TREK Travel Planner Missing Authorization Vulnerability (CVE-2026-40185)
slug: 2026-04-trek-auth-bypass
description: TREK collaborative travel planner before version 2.7.2 is vulnerable to missing authorization checks on the Immich trip photo management routes, potentially allowing unauthorized access to trip photos.
date: "2026-04-11T12:00:00Z"
severities:
  - medium
type: advisory
types:
  - advisory
tags:
  - cve-2026-40185
  - authorization-bypass
  - web-application
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40185
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40185
  - https://github.com/mauriceboe/TREK/commit/16277a3811a00c2983f7486fee83c112986cb179
  - https://github.com/mauriceboe/TREK/releases/tag/v2.7.2
  - https://github.com/mauriceboe/TREK/security/advisories/GHSA-pcr3-6647-jh72
iocs:
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious TREK Photo Route Access
    description: Detects potential unauthorized access to Immich trip photo management routes in TREK, indicating a possible CVE-2026-40185 exploitation attempt.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect TREK Version Less Than 2.7.2
    description: Detects web requests from TREK versions prior to 2.7.2, indicating potentially vulnerable systems.
    platform: sigma
    severity: medium
    tactics:
      - vulnerability
    data_sources:
      - webserver
      - linux
rules_count: 2
---

TREK is a collaborative travel planning application. Prior to version 2.7.2, a critical vulnerability existed within the application related to authorization checks. Specifically, the Immich trip photo management routes lacked proper authorization checks. This flaw, identified as CVE-2026-40185, could potentially allow unauthorized users to access and manipulate trip photos if exploited. The vulnerability was reported by GitHub, Inc. and patched in version 2.7.2 of TREK. Defenders should ensure they are running version 2.7.2 or later of the TREK application to mitigate this risk. This vulnerability affects systems running the vulnerable versions of the TREK application and could impact the confidentiality and integrity of user data.

## Attack Chain

1. An attacker identifies a vulnerable TREK instance running a version prior to 2.7.2.
2. The attacker crafts a malicious HTTP request targeting the Immich trip photo management routes.
3. Due to the missing authorization checks, the attacker bypasses authentication requirements.
4. The attacker gains unauthorized access to trip photos.
5. The attacker may modify or delete trip photos, impacting data integrity.
6. The attacker could potentially use the exposed data to gather sensitive information about the trip and its participants.
7. The attacker could potentially upload malicious images to the photo storage.

## Impact

Successful exploitation of CVE-2026-40185 can lead to unauthorized access and modification of trip photos within the TREK travel planner application. While the exact number of affected users is unknown, any TREK instance running a version prior to 2.7.2 is susceptible. This could result in a breach of confidentiality, potential data manipulation, and reputational damage for the application. Sectors that rely on collaborative travel planning may be particularly affected.

## Recommendation

*   Upgrade all TREK instances to version 2.7.2 or later to remediate CVE-2026-40185.
*   Deploy the Sigma rule `Detect Suspicious TREK Photo Route Access` to detect potential exploitation attempts targeting the vulnerable photo management routes.
*   Monitor web server logs for unusual activity related to the Immich trip photo management routes.
*   Monitor network traffic for unusual patterns or connections to the TREK server that might indicate exploitation attempts.
