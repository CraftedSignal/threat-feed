---
title: LiteLLM Privilege Escalation via /user/update Endpoint (CVE-2026-47102)
slug: 2026-05-litellm-privesc
description: CVE-2026-47102 describes a privilege escalation vulnerability in LiteLLM versions prior to 1.83.10, where the /user/update endpoint allows users to modify their own user_role, potentially escalating their privileges to proxy_admin.
date: "2026-05-21T21:18:40Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - CVE-2026-47102
  - web-application
vendors:
  - LiteLLM
products:
  - LiteLLM < 1.83.10
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-47102
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-47102
rules:
  - title: Detect CVE-2026-47102 Exploitation — LiteLLM User Role Update
    description: Detects CVE-2026-47102 exploitation — attempts to modify the user_role field via the /user/update endpoint in LiteLLM.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detect CVE-2026-47102 Exploitation — LiteLLM User Role Update via request body
    description: Detects CVE-2026-47102 exploitation — attempts to modify the user_role field via the /user/update endpoint in LiteLLM using a JSON request body.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
---

LiteLLM versions prior to 1.83.10 are vulnerable to a privilege escalation via the `/user/update` endpoint (CVE-2026-47102). The vulnerability stems from insufficient access controls on the fields that users can modify within their own account profile. While the endpoint correctly restricts users to only updating their own account, it fails to prevent modification of the `user_role` field. By exploiting this flaw, a standard user can elevate their privileges to `proxy_admin`, gaining unrestricted administrative control over LiteLLM, including all users, teams, keys, models, and prompt history. Users with the `org_admin` role can exploit this vulnerability without chaining any additional flaws, making internal threat actors a significant risk.

## Attack Chain

1. An attacker authenticates to the LiteLLM application with standard user credentials.
2. The attacker crafts a malicious HTTP request targeting the `/user/update` endpoint.
3. The HTTP request includes a modified `user_role` field set to `proxy_admin`.
4. The attacker sends the crafted HTTP request to the LiteLLM server.
5. The LiteLLM server, lacking proper input validation, accepts the modified `user_role` value.
6. The attacker's account is updated with the `proxy_admin` role in the LiteLLM database.
7. The attacker logs out and logs back in to refresh their permissions.
8. The attacker, now with `proxy_admin` privileges, can access and control all aspects of the LiteLLM platform.

## Impact

Successful exploitation of this vulnerability allows an attacker to gain full administrative control over the LiteLLM platform. This includes the ability to manage all users, teams, API keys, models, and prompt history. The attacker could potentially exfiltrate sensitive data, modify models, create new administrative accounts, or disrupt the service for all users. The vulnerability poses a significant risk to the confidentiality, integrity, and availability of the LiteLLM platform.

## Recommendation

*   Upgrade to LiteLLM version 1.83.10 or later to patch CVE-2026-47102.
*   Deploy the Sigma rule "Detect CVE-2026-47102 Exploitation — LiteLLM User Role Update" to monitor for malicious attempts to modify the `user_role` field via the `/user/update` endpoint.
*   Review access logs for unusual activity related to the `/user/update` endpoint, specifically focusing on POST requests with modifications to user roles.
