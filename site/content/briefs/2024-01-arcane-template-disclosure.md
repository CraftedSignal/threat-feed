---
title: Arcane Unauthenticated Compose Template Content Disclosure
slug: 2024-01-arcane-template-disclosure
description: Arcane versions before 1.18.0 are vulnerable to an unauthenticated information disclosure on four GET endpoints under `/api/templates*`, allowing unauthorized access to Compose YAML and `.env` content including sensitive secrets.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - information-disclosure
  - vulnerability
  - arcane
vendors:
  - GitHub
products:
  - Arcane (before 1.18.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public Fasing Application
references:
  - https://github.com/advisories/GHSA-cxx3-hr75-4q96
rules:
  - title: Detect Unauthenticated Access to Arcane Template Content
    description: Detects unauthenticated GET requests to the Arcane template content endpoint, indicating potential exploitation of CVE-2026-42461.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1592
    data_sources:
      - webserver
      - linux
  - title: Detect Listing of Arcane Templates
    description: Detects unauthenticated GET requests to the Arcane templates list endpoint.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Arcane versions prior to 1.18.0 are susceptible to an unauthenticated information disclosure vulnerability. The vulnerability stems from four `GET` endpoints under the `/api/templates*` path in Arcane's Huma backend that lack any security requirements. This design flaw allows any unauthenticated network client to list and read the full Compose YAML and `.env` content of every custom template stored in the instance. This includes sensitive information such as database passwords, API keys, and other secrets stored verbatim from the operator's environment variables due to the "Save as Template" workflow on project creation pages. This vulnerability poses a significant risk of exposing critical infrastructure secrets and internal service details.

## Attack Chain

1. An attacker identifies an Arcane instance running a version prior to 1.18.0.
2. The attacker sends an unauthenticated `GET` request to `/api/templates` to enumerate available templates, revealing names, descriptions, and tags.
3. The attacker sends an unauthenticated `GET` request to `/api/templates/{id}/content` to retrieve the content of a specific template.
4. The Arcane backend processes the request without authentication, due to missing security requirements on these endpoints.
5. The backend retrieves the requested template content, including the `Content` and `EnvContent` fields from the database.
6. The backend returns the template content to the attacker, including sensitive environment variables stored in plain text within the `EnvContent`.
7. The attacker extracts sensitive information, such as database passwords, API keys, and registry tokens, from the `EnvContent`.
8. The attacker uses the exposed credentials to gain unauthorized access to internal systems and services.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to access sensitive information stored within Arcane templates. This includes database passwords, API keys, and other secrets, potentially leading to unauthorized access to critical systems and data. The enumeration of templates also reveals internal services and infrastructure details, aiding further reconnaissance. This vulnerability affects any Arcane instance running a version prior to 1.18.0 where operators have stored sensitive information in custom Compose templates.

## Recommendation

- Upgrade Arcane to version 1.18.0 or later to patch the vulnerability (CVE-2026-42461).
- Deploy the following Sigma rule to detect suspicious access to the template content endpoints.
- Review existing templates for sensitive information and rotate any exposed credentials immediately.
- Implement network segmentation to limit access to the Arcane instance.
