---
title: Perfmatters WordPress Plugin Arbitrary File Overwrite Vulnerability (CVE-2026-4351)
slug: 2026-04-perfmatters-overwrite
description: The Perfmatters plugin for WordPress is vulnerable to arbitrary file overwrite via path traversal, allowing authenticated attackers with subscriber-level access to overwrite arbitrary files on the server with a fixed PHP docblock content, potentially causing denial of service.
date: "2026-04-10T02:37:36Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - wordpress
  - perfmatters
  - file-overwrite
  - path-traversal
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1555
    technique_name: Credentials from Password Stores
cves:
  - id: CVE-2026-4351
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4351
rules:
  - title: Detect Perfmatters Arbitrary File Overwrite Attempt
    description: Detects attempts to exploit the Perfmatters plugin arbitrary file overwrite vulnerability (CVE-2026-4351) via suspicious HTTP GET requests.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
  - title: Detect File Overwrite via file_put_contents with Traversal
    description: Detects file overwrite attempts using file_put_contents function combined with path traversal, indicative of potential exploitation of vulnerabilities like CVE-2026-4351.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1555
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Perfmatters plugin for WordPress, in versions up to and including 2.5.9, is vulnerable to an arbitrary file overwrite vulnerability (CVE-2026-4351). This vulnerability stems from the `PMCS::action_handler()` method's processing of bulk `activate`/`deactivate` actions without proper authorization checks or nonce verification. The unsanitized `$_GET['snippets'][]` values are then passed to `Snippet::activate()`/`Snippet::deactivate()`, which subsequently call `Snippet::update()` and `file_put_contents()` with a traversed path. An authenticated attacker with subscriber-level privileges can exploit this flaw to overwrite arbitrary files on the server with a fixed PHP docblock, leading to a potential denial-of-service condition by corrupting critical files such as `.htaccess` or `index.php`. This vulnerability allows low-privileged users to gain elevated privileges on the system.

## Attack Chain

1. Attacker authenticates to the WordPress site with subscriber-level access.
2. Attacker crafts a malicious HTTP GET request targeting the WordPress installation.
3. The GET request includes the `pmcs_action` parameter set to `bulk_activate` or `bulk_deactivate`.
4. The GET request includes the `snippets[]` parameter containing a path traversal payload, such as `../../../.htaccess`.
5. The `PMCS::action_handler()` function processes the request without proper authorization or nonce validation.
6. The `Snippet::activate()` or `Snippet::deactivate()` functions are called, leading to `Snippet::update()`.
7. `Snippet::update()` then calls `file_put_contents()` with the attacker-controlled path.
8. The attacker overwrites the targeted file (e.g., `.htaccess`, `index.php`) with a fixed PHP docblock, leading to a denial of service or further compromise.

## Impact

Successful exploitation allows an attacker to overwrite arbitrary files on the WordPress server. Overwriting critical files like `.htaccess` or `index.php` can result in a denial-of-service condition, rendering the website unavailable. In some cases, this could be leveraged for further compromise by injecting malicious code into other PHP files or modifying server configurations. The vulnerability affects all installations using the Perfmatters plugin version 2.5.9 or earlier.

## Recommendation

*   Immediately update the Perfmatters plugin to the latest version to patch CVE-2026-4351.
*   Deploy the Sigma rule `Detect Perfmatters Arbitrary File Overwrite Attempt` to monitor for exploitation attempts targeting this vulnerability via HTTP GET requests.
*   Monitor web server logs for suspicious GET requests containing `pmcs_action=bulk_activate` or `pmcs_action=bulk_deactivate` and path traversal sequences within the `snippets[]` parameter.
*   Implement strict file permission controls to limit the impact of potential file overwrite vulnerabilities.
