---
title: Directus Aggregate Query Vulnerability Allows Disclosure of Concealed Data
slug: 2026-04-directus-aggregate-disclosure
description: A vulnerability in Directus versions prior to 11.17.0 allows authenticated users to extract concealed field values, including static API tokens and two-factor authentication secrets from directus_users, via aggregate queries.
date: "2026-04-04T06:13:57Z"
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

Directus versions prior to 11.17.0 contain a vulnerability where aggregate functions, such as `min` and `max`, when applied to fields with the `conceal` special type, incorrectly return raw database values instead of the masked placeholder. This affects authenticated users who have read access to the affected collection, enabling them to extract concealed field values via `groupBy` aggregate queries.  This vulnerability allows for the extraction of sensitive information, such as static API…
