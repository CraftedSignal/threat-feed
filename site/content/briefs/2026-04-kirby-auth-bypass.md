---
title: Kirby CMS Authorization Bypass via Blueprint Injection
slug: 2026-04-kirby-auth-bypass
description: An authorization bypass vulnerability in Kirby CMS allows authenticated users to perform actions they should not be allowed to perform based on their configured permissions by injecting custom dynamic blueprint configuration into the model data, leading to privilege escalation.
date: "2026-04-25T12:00:00Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - authorization-bypass
  - privilege-escalation
  - web-application
vendors:
  - getkirby
products:
  - Kirby CMS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://github.com/advisories/GHSA-6gqr-mx34-wh8r
  - https://github.com/getkirby/kirby/releases/tag/4.9.0
  - https://github.com/getkirby/kirby/releases/tag/5.4.0
  - https://github.com/getkirby/kirby/releases
rules:
  - title: Detect Kirby CMS Blueprint Injection
    description: Detects attempts to inject dynamic blueprint configurations into Kirby CMS during page, file, or user creation by monitoring POST requests with suspicious parameters.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
  - title: Detect Kirby CMS Unauthorized User Creation
    description: Detects attempts to create new users when the logged in user shouldn't have the permission to do so.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A high-severity authorization bypass vulnerability has been identified in Kirby CMS versions prior to 4.9.0 and between 5.0.0 and 5.4.0. The vulnerability allows authenticated users to perform actions they should not be authorized to perform, such as creating pages, files, or users, even if their roles lack the necessary permissions (`pages.create`, `files.create`, or `users.create`). This bypass occurs due to the injection of custom dynamic blueprint configurations into the model data during the creation process. By manipulating the `options` parameter, an attacker can override intended permissions and options configured by the site developer in the user and model blueprints. The vulnerability was reported by @offset and patched in Kirby 4.9.0 and 5.4.0.

## Attack Chain

1.  An attacker authenticates to the Kirby CMS with a valid user account that lacks the `pages.create`, `files.create`, or `users.create` permissions.
2.  The attacker crafts a malicious HTTP request to create a new page, file, or user.
3.  The malicious request injects a custom dynamic blueprint configuration into the model data via the `options` parameter. This injected configuration includes `'create' => true`, effectively overriding the default permission settings.
4.  Kirby CMS processes the request without properly sanitizing or validating the injected blueprint configuration.
5.  The injected `options` parameter overrides the permissions configured in the user blueprint and/or the blueprint of the target model.
6.  The system incorrectly authorizes the user to create the page, file, or user, despite their role not having the necessary permissions.
7.  The new page, file, or user is successfully created with the attacker's injected configuration.
8.  The attacker has successfully escalated their privileges and can now perform actions they were not intended to perform.

## Impact

Successful exploitation of this vulnerability allows authenticated users to bypass intended permission controls and perform unauthorized actions within the Kirby CMS. This can lead to unauthorized content creation, modification, or deletion, potentially compromising the integrity and confidentiality of the website. An attacker could create administrative accounts, modify critical pages, or upload malicious files, leading to a full compromise of the Kirby CMS instance. The severity is high because any authenticated user can exploit it if the site is misconfigured.

## Recommendation

*   Upgrade to Kirby CMS version 4.9.0 or 5.4.0 or later to apply the patch that filters the `blueprint` property during the creation of pages, files, and users.
*   Review user and model blueprints to ensure permissions are correctly configured, specifically for `pages.create`, `files.create`, and `users.create`.
*   Monitor web server logs for suspicious POST requests to endpoints responsible for creating pages, files, or users.
*   Implement the Sigma rule `Detect Kirby CMS Blueprint Injection` to detect attempts to inject dynamic blueprint configurations via HTTP requests.
