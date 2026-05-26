---
title: Mattermost File Access Vulnerability (CVE-2026-3473)
slug: 2026-05-mattermost-file-access
description: Mattermost versions 11.6.x <= 11.6.0, 11.5.x <= 11.5.3, 11.4.x <= 11.4.4, 10.11.x <= 10.11.14 fail to validate file ownership and access control, allowing an authenticated user to access and download files belonging to other users or teams via crafted Boards API requests using valid file IDs.
date: "2026-05-26T13:30:28Z"
type: threat
types:
  - threat
severities:
  - medium
cpes:
  - cpe:2.3:a:mattermost:mattermost_server:*:*:*:*:*:*:*:*
tags:
  - cve
  - vulnerability
  - mattermost
  - authorization bypass
vendors:
  - Mattermost Inc.
products:
  - Mattermost Server
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1539
    technique_name: Steal Web Session Cookie
cves:
  - id: CVE-2026-3473
    cvss: 5.9
    epss: 0.00028
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3473
  - https://mattermost.com/security-updates
rules:
  - title: Detect CVE-2026-3473 Exploitation Attempt - Mattermost Boards API File Access
    description: Detects potential exploitation of CVE-2026-3473 where an authenticated user attempts to access files via the Mattermost Boards API with a GET request.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1539
    data_sources:
      - webserver
rules_count: 1
---

Mattermost, a popular open-source collaboration platform, is vulnerable to an authorization bypass issue. CVE-2026-3473 affects Mattermost Server versions 11.6.x <= 11.6.0, 11.5.x <= 11.5.3, 11.4.x <= 11.4.4, and 10.11.x <= 10.11.14. This vulnerability stems from a failure to properly validate file ownership and access control. An authenticated user can exploit this flaw to gain unauthorized access to and download files belonging to other users or teams. The attack is carried out via crafted Boards API requests utilizing valid file IDs. This vulnerability is identified by Mattermost Advisory ID MMSA-2026-00620. Successful exploitation can lead to sensitive data exposure and potential compromise of confidential information within the Mattermost environment.

## Attack Chain

1. An attacker authenticates to a vulnerable Mattermost server.
2. The attacker identifies a valid file ID belonging to another user or team.
3. The attacker crafts a malicious Boards API request.
4. The crafted API request includes the valid file ID of the target file.
5. The vulnerable Mattermost server fails to properly validate file ownership and access control.
6. The server processes the request without proper authorization checks.
7. The server grants the attacker access to the file.
8. The attacker successfully downloads the file.

## Impact

Successful exploitation of CVE-2026-3473 allows an authenticated user to access and download files belonging to other users or teams within the Mattermost instance. This could lead to the unauthorized disclosure of sensitive information, including confidential documents, private communications, and other proprietary data. The impact is significant for organizations that rely on Mattermost for secure internal communication and collaboration. The number of affected installations is currently unknown.

## Recommendation

*   Upgrade Mattermost Server to a patched version (later than 11.6.0, 11.5.3, 11.4.4, or 10.11.14) to remediate CVE-2026-3473 as per the vendor advisory.
*   Monitor webserver logs for unusual activity related to the Boards API, specifically requests attempting to access files using file IDs (cs-uri-stem|contains: "/api/v1/boards").
*   Deploy the Sigma rule provided to detect suspicious access to the Boards API.
*   Enforce strict file access control policies within Mattermost to limit the potential impact of similar vulnerabilities.
