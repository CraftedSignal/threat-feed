---
title: Directus Aggregate Query Vulnerability Allows Disclosure of Concealed Data
slug: 2026-04-directus-aggregate-disclosure
description: A vulnerability in Directus versions prior to 11.17.0 allows authenticated users to extract concealed field values, including static API tokens and two-factor authentication secrets from directus_users, via aggregate queries.
date: "2026-04-04T06:13:57Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - directus
  - vulnerability
  - credential-access
  - api-token
  - 2fa-bypass
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1212
    technique_name: Exploitation of Credentials
references:
  - https://github.com/advisories/GHSA-38hg-ww64-rrwc
rules:
  - title: Detect Aggregate Queries Targeting Concealed Fields in Directus
    description: Detects aggregate queries with groupBy targeting collections known to contain concealed fields (e.g., directus_users) in Directus installations.  This may indicate attempts to exploit CVE-2026-35442.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1212
    data_sources:
      - webserver
      - linux
  - title: Detect Directus API Token Extraction via Aggregate Query
    description: Detects attempts to extract API tokens from Directus using aggregate queries, specifically targeting the directus_users collection and the 'token' field.
    platform: sigma
    severity: critical
    tactics:
      - credential_access
    techniques:
      - T1212
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Directus versions prior to 11.17.0 contain a vulnerability where aggregate functions, such as `min` and `max`, when applied to fields with the `conceal` special type, incorrectly return raw database values instead of the masked placeholder. This affects authenticated users who have read access to the affected collection, enabling them to extract concealed field values via `groupBy` aggregate queries.  This vulnerability allows for the extraction of sensitive information, such as static API tokens and two-factor authentication secrets stored in `directus_users`, enabling account takeovers and 2FA bypass. The vulnerability was reported on April 4, 2026, and is identified as CVE-2026-35442. Defenders should prioritize upgrading Directus instances to version 11.17.0 or later to mitigate this risk.

## Attack Chain

1. Attacker authenticates to a vulnerable Directus instance with valid user credentials.
2. Attacker identifies a collection containing fields with the `conceal` special type, such as `directus_users`.
3. Attacker crafts an aggregate query using functions like `min` or `max` on the concealed field and includes a `groupBy` clause. Example: `SELECT min(secret_field) FROM collection GROUP BY other_field`.
4. The Directus server processes the aggregate query but fails to properly apply the masking logic to the nested results.
5. The server returns the raw, unmasked values of the concealed field in the aggregate query response.
6. The attacker extracts static API tokens and TOTP seeds from the returned data.
7. Attacker uses the extracted API tokens to authenticate as other users, including administrators, bypassing username/password requirements.
8. Attacker uses the extracted TOTP seeds to bypass two-factor authentication for other users, gaining unauthorized access to their accounts.

## Impact

Successful exploitation of this vulnerability can lead to complete account takeover, including administrative accounts. Two-factor authentication mechanisms can be bypassed, invalidating this security control. The number of affected organizations depends on the adoption rate of Directus, but all instances running versions prior to 11.17.0 are vulnerable. If the attack succeeds, attackers gain full control over the Directus instance and associated data, potentially leading to data breaches, service disruption, and reputational damage.

## Recommendation

*   Upgrade Directus to version 11.17.0 or later to patch the vulnerability (CVE-2026-35442).
*   Implement a Web Application Firewall (WAF) rule to detect and block aggregate queries targeting concealed fields in sensitive collections. See the Sigma rule example for guidance.
*   Monitor Directus application logs for unusual aggregate query patterns, especially those involving `groupBy` and functions like `min` or `max`.
