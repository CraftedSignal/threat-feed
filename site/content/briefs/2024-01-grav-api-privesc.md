---
title: Grav API Plugin Privilege Escalation Vulnerability
slug: 2024-01-grav-api-privesc
description: A privilege escalation vulnerability in the Grav API plugin allows authenticated users with basic API access to elevate their privileges to Super Administrator, leading to full system compromise and potential remote code execution.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - web-application
  - grav
vendors:
  - getgrav
products:
  - grav-plugin-api (< 1.0.0-beta.15)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-r945-h4vm-h736
rules:
  - title: Detect Grav API User Permission Escalation Attempt
    description: Detects attempts to escalate user privileges in Grav CMS by sending PATCH requests to the /api/v1/users/ endpoint to modify the 'access' parameter.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Grav API Authentication for User
    description: Detects authentication to the Grav API for a specific user.
    platform: sigma
    severity: informational
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A critical vulnerability exists within the Grav API plugin (`composer/getgrav/grav-plugin-api`) versions prior to 1.0.0-beta.15. This vulnerability, identified as CVE-2026-42843, allows any authenticated user with the `api.access` permission to escalate their privileges to Super Administrator. The flaw is due to an insecure direct object reference and logic error in the `UsersController::update` method, specifically in how user permissions are updated via the API. By sending a crafted PATCH request, a low-privileged user can modify their own access control list (ACL) to include `admin.super` and `api.super` permissions. Successful exploitation grants the attacker full control over the Grav CMS instance.

## Attack Chain

1. Attacker obtains a low-privileged user account with `api.access` permission on the Grav CMS.
2. The attacker authenticates to the Grav API using the obtained credentials to receive a valid JWT access token via a POST request to `/api/v1/auth/token`.
3. The attacker crafts a malicious PATCH request to the `/api/v1/users/{username}` endpoint, targeting their own username.
4. The PATCH request includes a JSON payload that modifies the user's `access` field, specifically setting `admin.super` and `api.super` to `true`. For example: `{"access":{"admin":{"login":true,"super":true},"api":{"access":true,"super":true},"site":{"login":true}}}`.
5. The attacker sends the crafted PATCH request to the target Grav CMS instance, including the JWT access token in the `X-API-Token` header.
6. The vulnerable `UsersController::update` method in `user/plugins/api/classes/Api/Controllers/UsersController.php` processes the request without properly validating the user's authority to modify their own permissions.
7. The user's `access` field is updated with the malicious payload, granting them Super Administrator privileges.
8. The attacker logs into the Grav Admin panel using the compromised user credentials and now has full control over the Grav CMS, able to modify content, install plugins, and potentially execute arbitrary code.

## Impact

This privilege escalation vulnerability (CVE-2026-42843) allows any low-privileged user to gain complete control over a Grav CMS instance. An attacker can modify website content, inject malicious code, install backdoors, and potentially achieve remote code execution (RCE) on the underlying server by modifying Twig templates. This can lead to data breaches, website defacement, and complete compromise of the affected system.

## Recommendation

*   Upgrade the `composer/getgrav/grav-plugin-api` package to version 1.0.0-beta.15 or later to patch CVE-2026-42843.
*   Deploy the Sigma rule "Detect Grav API User Permission Escalation Attempt" to identify attempted exploitation of this vulnerability by monitoring for PATCH requests to `/api/v1/users/` with modified access parameters.
