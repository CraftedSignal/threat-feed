---
title: Laravel Backpack CRUD Mass Assignment Vulnerability
slug: 2026-08-laravel-backpack-mass-assignment
description: An authenticated mass-assignment vulnerability in Laravel Backpack CRUD allows an attacker with a session to update arbitrary user model attributes, leading to password reset, email hijacking, or privilege escalation.
date: "2026-08-20T19:13:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - web-application
  - php
  - laravel
vendors:
  - Laravel Backpack
products:
  - CRUD (< 6.8.11, >= 7.0.0-alpha.1, < 7.0.34)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1565.001
    technique_name: Data Manipulation
    evidence: The controller uses except(['_token']) rather than $request->validated() or the restricted keys, any column present in the user model's $fillable array is mass-assigned.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1565.001
    technique_name: Data Manipulation
    evidence: Any attacker holding an authenticated Backpack session can permanently take over the account by issuing one POST that includes password.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xpv2-hrfc-hw62
  - https://nvd.nist.gov/vuln/detail/CVE-2026-54175
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade backpack/crud to versions >= 6.8.11 or >= 7.0.34
      owner: Development
      due: 48h
      evidence: Source advisory recommends upgrading to these versions to resolve CVE-2026-54175
  mitigation_plan:
    - priority: immediate
      action: Review App\Models\User $fillable array for sensitive fields
      owner: Development
      addresses: CVE-2026-54175
      evidence: Source notes that mass-assignment allows modifying any column in the $fillable array
---

Laravel Backpack CRUD, a popular administration panel package for Laravel, contains a critical mass-assignment vulnerability (CVE-2026-54175) in the `MyAccountController::postAccountInfoForm` method. The controller updates the current user's profile by passing `$request->except(['_token'])` directly to the `update()` method of the Eloquent user model. Because this approach lacks an allowlist, any database column present in the user model's `$fillable` array can be overwritten by the request body.

This vulnerability is particularly dangerous for applications using default Laravel user models where `password` is marked as fillable. An attacker who has hijacked an active administrator session (e.g., via session token theft or residual access on a shared workstation) can POST arbitrary password data to the `/admin/edit-account-info` endpoint. Unlike the dedicated password change route, this endpoint does not enforce the verification of the current password. Successful exploitation transforms a transient session into persistent account takeover. The flaw also facilitates privilege escalation if other security-sensitive fields (e.g., `role_id`, `is_admin`) are defined as fillable.

## Impact

Successful exploitation results in unauthorized account modification, enabling persistent account takeover without knowledge of the victim's credentials. Attackers can also redirect administrative traffic by modifying the `email` field to trigger future password resets or elevate their own privileges by modifying authorization-related columns if they are present in the model's fillable definition. The scope of impact is limited to authenticated users; however, it effectively bypasses multi-factor and password-verification controls intended for security-sensitive account changes.

## Recommendation

1. Patch immediately by upgrading `backpack/crud` to versions `>= 6.8.11` or `>= 7.0.34`.
2. For applications where immediate patching is not possible, override the `MyAccountController` or implement a middleware to sanitize the incoming request to `postAccountInfoForm` using an explicit `$request->only()` allowlist for fields such as `name` and the email attribute.
3. Review the `App\Models\User` model to ensure that security-sensitive attributes like `role_id`, `is_admin`, or `two_factor_secret` are not included in the `$fillable` array.
