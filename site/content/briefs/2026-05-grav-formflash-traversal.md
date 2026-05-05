---
title: Grav CMS FormFlash Unauthenticated Path Traversal and Arbitrary File Write
slug: 2026-05-grav-formflash-traversal
description: Grav CMS is vulnerable to an unauthenticated path traversal vulnerability within the FormFlash component, allowing attackers to create arbitrary directories and write files, leading to configuration injection and potential denial of service; fixed in version 2.0.0-beta.2.
date: "2026-05-06T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - file-write
  - gravcms
vendors:
  - Grav
products:
  - grav (versions < 2.0.0-beta.2)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
references:
  - https://github.com/advisories/GHSA-hmcx-ch82-3fv2
  - https://github.com/getgrav/grav/commit/d904efc33
rules:
  - title: Detect GravCMS FormFlash Path Traversal Attempt
    description: Detects attempts to exploit the GravCMS FormFlash path traversal vulnerability by identifying POST requests with suspicious `__form-flash-id` parameters.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect Arbitrary File Write via GravCMS FormFlash
    description: Detects creation of index.yaml files in suspicious directories via GravCMS FormFlash exploit.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1555
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Grav CMS versions prior to 2.0.0-beta.2 are susceptible to an unauthenticated path traversal vulnerability in the FormFlash component. This flaw allows unauthenticated attackers to manipulate the `__form-flash-id` parameter in POST requests, injecting path traversal sequences to create arbitrary directories and write malicious `index.yaml` files. This vulnerability stems from a lack of sanitization of the `session_id` parameter within the FormFlash class. Successful exploitation can lead to configuration injection, data integrity issues, cross-user data interference, and potential denial-of-service conditions through inode exhaustion. The vulnerability was confirmed in Grav v1.7.49.5 and the development branch as of March 2026, and is addressed in commit `d904efc33` on the 2.0 branch, which will ship in version 2.0.0-beta.2.

## Attack Chain

1.  The attacker identifies a Grav CMS page containing a form (e.g., `/contact`).
2.  The attacker intercepts the POST request generated during form submission.
3.  The attacker modifies the `__form-flash-id` parameter in the POST request to include a path traversal sequence (e.g., `../../user/config/poc_dir`).
4.  The attacker submits the modified POST request to the server.
5.  The vulnerable `FormFlash` class processes the unsanitized `__form-flash-id` parameter.
6.  The application attempts to create a directory based on the traversed path using `locator->findResource`.
7.  An arbitrary directory is created at the specified location (e.g., `/var/www/html/user/config/poc_dir/poc/`).
8.  An `index.yaml` file is written to the newly created directory containing attacker-controlled data.

## Impact

Successful exploitation of this vulnerability allows unauthenticated attackers to achieve several malicious outcomes. Attackers can inject malicious configurations by writing `index.yaml` files into plugin/theme configuration directories, leading to altered application behavior and potential compromise. Cross-user data interference becomes possible, allowing attackers to overwrite temporary form data of other users. Data integrity is compromised through unauthorized modification of configuration subfolders, potentially leading to site corruption. Finally, attackers can trigger a denial-of-service condition by exhausting disk space or inodes through recursive directory creation.

## Recommendation

*   Apply a strict alphanumeric regex to the `session_id` in the `FormFlash` class to prevent path traversal, as implemented in Grav 2.0.0-beta.2 (commit `d904efc33`).
*   Monitor web server logs for POST requests to form endpoints with `__form-flash-id` parameters containing path traversal sequences like `../` using the provided Sigma rules.
*   Upgrade to Grav CMS version 2.0.0-beta.2 or later, which includes the fix for CVE-2026-42608.
