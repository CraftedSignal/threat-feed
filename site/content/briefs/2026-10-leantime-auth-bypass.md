---
title: Leantime JSON-RPC Privilege Escalation
slug: 2026-10-leantime-auth-bypass
description: Authenticated users can escalate privileges to administrator or manage plugins by invoking unauthorized JSON-RPC methods in Leantime.
date: "2026-10-15T22:24:38Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - json-rpc
  - authentication-bypass
vendors:
  - Leantime
products:
  - Leantime
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Any authenticated Leantime user - including the lowest-privilege readonly role - can escalate to full administrative access by calling the JSON-RPC method leantime.rpc.api.api.createApiKeyWithProjects.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-54mm-6729-r5wp
rules:
  - title: Detect Leantime Unauthorized JSON-RPC Method Calls
    description: Detects potential exploitation of Leantime by monitoring JSON-RPC calls to sensitive methods from potentially unauthorized sessions
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Leantime to the latest version
      owner: IT Operations
      due: 24h
      evidence: Vendor security advisory
  hunt_leads:
    - lead: Search logs for successful POST /api/jsonrpc calls involving 'createApiKeyWithProjects'
      technique_id: T1068
      data_needed:
        - Web server logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit path described in the source
  mitigation_plan:
    - priority: immediate
      action: Patch instance
      owner: IT Operations
      addresses: Privilege Escalation
      evidence: GHSA-54mm-6729-r5wp
---

Leantime contains a critical authorization vulnerability where multiple JSON-RPC service methods are exposed without necessary role-based access control. The application utilizes a `PermissionEnforcer` class that relies on a `#[RequiresPermission]` PHP attribute to gate access; however, when this attribute is missing, the enforcer fails open, permitting any authenticated user to execute the method. This affects sensitive administrative functions, specifically `leantime.rpc.api.api.createApiKeyWithProjects`, which allows an attacker to create new accounts with arbitrary roles, and plugin management methods like `installPlugin` and `enablePlugin`. Because the application's first-party JavaScript client uses `X-Requested-With: XMLHttpRequest` headers to authenticate via session cookies, an attacker can leverage their existing, low-privilege session to trigger these methods directly via the JSON-RPC endpoint.

## Attack Chain

1. Attacker authenticates to a Leantime instance with a low-privileged account (e.g., 'readonly' role).
2. Attacker verifies the current session is active by capturing the session cookie from the browser or application traffic.
3. Attacker crafts a JSON-RPC POST request targeting the `/api/jsonrpc` endpoint.
4. Attacker includes the required `X-Requested-With: XMLHttpRequest` header to ensure the session middleware processes the authenticated request.
5. Attacker calls the `leantime.rpc.api.api.createApiKeyWithProjects` method, supplying a JSON payload with `role` set to 40 (Admin).
6. The backend processes the request without checking the caller's privileges, creating a new administrative user.
7. Attacker receives the new credentials (username/password) in the JSON-RPC response body.
8. Attacker logs into the application using the escalated credentials to gain full administrative access.

## Impact

Successful exploitation allows any authenticated user to achieve full administrative control over the Leantime instance. By creating administrative accounts or manipulating plugins, an attacker can perform unauthorized data access, system configuration changes, and potentially achieve remote code execution through the installation of malicious plugins. This affects all Leantime instances that have not yet applied the vendor's security update.

## Recommendation

* Update Leantime immediately to the patched version provided by the vendor.
* Monitor HTTP traffic for POST requests to `/api/jsonrpc` that originate from low-privilege users or IP addresses not associated with authorized administrative workstations.
* Enable web application firewall (WAF) rules to inspect and validate JSON-RPC method calls against a known-good allowlist of permitted administrative methods.
* Audit existing user accounts for suspicious additions or modifications to user roles, specifically looking for accounts created via automated API workflows.
