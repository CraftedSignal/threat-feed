---
title: Grav CMS API Blueprint Upload Privilege Escalation
slug: 2024-01-grav-api-privesc
description: A low-privileged authenticated API user with `api.media.write` can abuse `/api/v1/blueprint-upload` in Grav CMS to write an arbitrary YAML file into `user/accounts/`, enabling creation of a super-admin account and leading to full administrative compromise of the Grav API.
date: "2026-05-06T21:19:21Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - gravcms
  - privilege-escalation
  - yaml-injection
vendors:
  - getgrav
products:
  - grav
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-6xx2-m8wv-756h
rules:
  - title: Detect Grav CMS Malicious Blueprint Upload
    description: Detects attempts to upload malicious blueprints to the user/accounts directory in Grav CMS via the API, indicating potential privilege escalation.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1555
      - T1555.003
    data_sources:
      - webserver
      - linux
  - title: Detect Grav CMS New Admin User Creation via API
    description: Detects the creation of a new admin user via the API endpoint, which could be a result of the blueprint upload vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1555
      - T1555.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability in Grav CMS version `2.0.0-beta.2` allows a low-privileged, authenticated API user to escalate privileges to a super administrator. This flaw resides in the `/api/v1/blueprint-upload` endpoint. By manipulating the `destination` and `scope` parameters, an attacker can write an arbitrary YAML file into the `user/accounts/` directory. This circumvents intended access controls, allowing the creation of a new administrator account with `api.super` privileges. Exploitation requires only `api.media.write` access. Successful exploitation leads to complete control over the CMS management API, potentially enabling further attacks such as code execution. This vulnerability was disclosed on May 6, 2026, and poses a significant threat to Grav CMS installations using the API plugin.

## Attack Chain

1. Attacker authenticates to the Grav CMS API using a low-privileged account with `api.media.write` permissions.
2. The attacker crafts a malicious HTTP POST request to `/api/v1/blueprint-upload`.
3. The request includes multipart form data with the `destination` parameter set to `self@:` and the `scope` parameter set to `users/anything`.
4. The request includes a `file` parameter containing a YAML file crafted to create a new admin user, including setting a plaintext password and `api.super` access.
5. The Grav CMS API resolves the file path based on the `destination` and `scope` parameters, writing the malicious YAML file to the `user/accounts/` directory.
6. The attacker authenticates to the Grav CMS API using the newly created admin user credentials defined in the YAML file.
7. The attacker successfully logs in as a super administrator, gaining full access to the Grav CMS management API.
8. The attacker leverages their elevated privileges to modify content, alter configurations, manage users, or install malicious plugins/themes, ultimately achieving complete CMS compromise.

## Impact

Successful exploitation grants an attacker full control over the Grav CMS instance.  An attacker can modify website content, alter configurations, manage users (including creating additional administrator accounts), install or update plugins/themes, and access system-level administration features. This can lead to complete CMS compromise, potentially resulting in data theft, defacement, or further exploitation, such as server-side code execution. The vulnerability allows any user with limited API access (`api.media.write`) to create a super administrator account, drastically increasing the attack surface and potential for widespread damage.

## Recommendation

*   Upgrade Grav CMS to version `2.0.0-beta.4` or later to patch the vulnerability as per the advisory (https://github.com/advisories/GHSA-6xx2-m8wv-756h).
*   Deploy the Sigma rule `Detect Grav CMS Malicious Blueprint Upload` to detect attempts to exploit this vulnerability by monitoring for suspicious blueprint uploads to the `user/accounts` directory.
*   Implement the Sigma rule `Detect Grav CMS New Admin User Creation via API` to identify the creation of new admin users via the API endpoint.
*   Restrict `api.media.write` permissions to only trusted users, reducing the potential attack surface.
