---
title: Connect CMS Improper Authorization Vulnerability
slug: 2024-01-connect-cms-authz
description: An improper authorization vulnerability in Connect CMS allows authenticated users to modify arbitrary user profile information, potentially leading to account takeover and unauthorized data modification on affected versions 1.x <= 1.41.0 and 2.x <= 2.41.0.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - connect-cms
  - authorization
  - account-takeover
  - web-application
vendors:
  - Connect CMS
products:
  - Connect CMS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-qr6x-wvxr-8hm9
rules:
  - title: Connect CMS Profile Update Manipulation
    description: Detects attempts to manipulate user profiles in Connect CMS by identifying requests with modified user identifiers in the profile update endpoint.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Connect CMS Password Reset Attempt via Profile Update
    description: Detects suspicious password reset attempts by looking for password modification in the profile update functionality of Connect CMS.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Connect CMS is susceptible to an improper authorization vulnerability within its My Page profile update feature. This flaw allows an authenticated attacker to modify the profile information of other users, potentially leading to account takeover. The vulnerability resides in versions 1.x series <= 1.41.0 and 2.x series <= 2.41.0 of Connect CMS. Successful exploitation could allow attackers to change passwords, email addresses, or other sensitive data associated with targeted user accounts. This issue was reported by Sho Odagiri of GMO Cybersecurity by Ierae, Inc. on March 23, 2026, and affects any Connect CMS instance running the vulnerable versions, creating a significant risk for organizations relying on this CMS for their web presence. It is crucial for defenders to identify and patch vulnerable instances to prevent potential account compromise and data breaches.

## Attack Chain

1. An attacker authenticates to the Connect CMS application with valid credentials.
2. The attacker identifies the vulnerable My Page profile update feature.
3. The attacker crafts a malicious HTTP request targeting the profile update endpoint.
4. In the crafted request, the attacker manipulates the user identifier parameter (e.g., user ID, username) to specify the target user's account.
5. The attacker modifies profile information within the request body (e.g., email address, password).
6. The attacker sends the crafted request to the Connect CMS server.
7. Due to the improper authorization, the server processes the request without verifying if the attacker has permission to modify the target user's profile.
8. The target user's profile is updated with the attacker-supplied information, potentially leading to account takeover.

## Impact

Successful exploitation of this vulnerability can lead to the complete takeover of arbitrary user accounts within the Connect CMS platform. Affected organizations could experience unauthorized access to sensitive data, data breaches, and reputational damage. This vulnerability could affect any organization using a vulnerable version of Connect CMS, potentially impacting thousands of users if left unpatched. The impact is significant because account takeover can lead to further lateral movement within an organization's systems, depending on the privileges associated with the compromised accounts.

## Recommendation

*   Immediately upgrade Connect CMS installations to versions 1.41.1 or 2.41.1 or later to patch CVE-2026-32300.
*   Implement web application firewall (WAF) rules to detect and block suspicious requests targeting the profile update endpoint, filtering for manipulated user identifier parameters.
*   Deploy the Sigma rule `Connect CMS Profile Update Manipulation` to detect attempts to modify user profiles through the vulnerable endpoint based on HTTP request parameters.
