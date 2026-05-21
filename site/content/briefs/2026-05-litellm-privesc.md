---
title: LiteLLM Privilege Escalation via API Key Creation (CVE-2026-47101)
slug: 2026-05-litellm-privesc
description: LiteLLM versions prior to 1.83.14 allow an authenticated internal user to create API keys that bypass role-based access controls, potentially leading to full privilege escalation to proxy_admin due to a lack of verification of specified routes within the user's own permissions (CVE-2026-47101).
date: "2026-05-21T21:18:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - vulnerability
  - CVE-2026-47101
vendors:
  - LiteLLM
products:
  - LiteLLM < 1.83.14
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-47101
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-47101
rules:
  - title: Detect API Key Creation with Elevated Permissions
    description: Detects CVE-2026-47101 — API key creation with admin-only routes by internal users, indicating a privilege escalation attempt.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-47101
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect API Access Using Newly Created Key
    description: Detects API access to admin-only routes using a recently created API key, potentially indicating a privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - cve-2026-47101
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

LiteLLM versions prior to 1.83.14 are vulnerable to a privilege escalation flaw. An authenticated `internal_user` can create API keys with permissions exceeding their assigned roles. The vulnerability exists because the `allowed_routes` field is stored without validating that the specified routes are within the user's authorized permissions. By creating a key with access to `admin-only` routes, the attacker can bypass role-based access controls and elevate their privileges to `proxy_admin`. This allows the attacker to perform actions normally restricted to administrators, such as accessing sensitive data, modifying configurations, or disrupting services. Defenders should upgrade to version 1.83.14 or later to mitigate this vulnerability.

## Attack Chain

1. Attacker authenticates as an `internal_user`.
2. Attacker initiates the API key creation process.
3. Attacker specifies `allowed_routes` that include `admin-only` routes.
4. The system stores the `allowed_routes` without proper validation against the user's permissions.
5. Attacker obtains the newly created API key.
6. Attacker uses the API key to access the `admin-only` routes.
7. The system incorrectly authorizes the request based on the API key's `allowed_routes`, bypassing role-based access controls.
8. Attacker successfully executes actions normally restricted to `proxy_admin`, achieving full privilege escalation.

## Impact

Successful exploitation of this vulnerability allows an attacker to escalate their privileges from `internal_user` to `proxy_admin`. This grants the attacker full control over the LiteLLM instance, potentially leading to unauthorized access to sensitive data, modification of system configurations, and disruption of services. The severity is high due to the potential for complete system compromise and the ease of exploitation once the initial authentication is achieved.

## Recommendation

*   Upgrade LiteLLM to version 1.83.14 or later to patch CVE-2026-47101.
*   Implement the "Detect API Key Creation with Elevated Permissions" Sigma rule to identify attempts to create API keys with unauthorized routes.
*   Implement the "Detect API Access Using Newly Created Key" Sigma rule to identify unauthorized API access using newly created API keys.
