---
title: Grav CMS Twig Sandbox Vulnerability Allows Plugin Secret Exfiltration
slug: 2026-05-grav-twig-rce
description: A vulnerability in the Grav CMS Twig sandbox allow-list allows any user with the `admin.pages` role to call `config.toArray()` from within a page body, dumping the entire merged site configuration, including all plugin secrets, into the rendered HTML.
date: "2026-05-13T15:32:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - grav
  - twig
  - rce
  - secret-exfiltration
vendors:
  - Grav
products:
  - Grav (<= 2.0.0-rc.1)
references:
  - https://github.com/advisories/GHSA-j274-39qw-32c9
  - CVE-2026-44738
rules:
  - title: Detect Grav CMS Config Exfiltration via Twig
    description: Detects CVE-2026-44738 exploitation — Attempt to exfiltrate Grav CMS configuration via Twig template injection by calling config.toArray()
    platform: sigma
    severity: high
    tactics:
      - credential_access
    data_sources:
      - webserver
  - title: Detect POST Request to Save a Page with Malicious Frontmatter
    description: Detects POST requests to save a page with twig enabled and config.toArray() function which may indicate a config exfiltration
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    data_sources:
      - webserver
rules_count: 2
---

A vulnerability exists in Grav CMS version 2.0.0-rc.1 and earlier that allows users with the `admin.pages` role to exfiltrate sensitive configuration data. The Twig sandbox configuration permits calls to the `Config::toArray()` method, which exposes the entire merged site configuration, including plugin secrets. An editor-role user can inject a Twig code snippet into a page's content, causing the full configuration to be rendered as JSON within the HTML. This issue was reported on May 13, 2026, and poses a significant risk to Grav CMS deployments by allowing unauthorized access to sensitive credentials. No administrator privileges are required for this exploit, broadening the attack surface.

## Attack Chain

1. Attacker obtains editor-level access (`admin.pages` role) to the Grav CMS admin panel.
2. Attacker crafts a page with `process.twig: true` in the frontmatter to enable Twig processing.
3. Attacker inserts the payload `{{ config.toArray()|json_encode|raw }}` into the page body.
4. Attacker saves the page through the admin panel.
5. The Grav CMS renders the page, executing the Twig code.
6. The `config.toArray()` function dumps the entire merged site configuration as a JSON string.
7. The JSON string, containing sensitive plugin secrets, is embedded within the rendered HTML of the page.
8. Attacker accesses the rendered page, extracts the JSON string, and obtains plugin credentials.

## Impact

Successful exploitation allows any user with the editor role (`admin.pages`) to exfiltrate all plugin credentials stored in the Grav CMS site configuration. This includes sensitive information such as SMTP passwords, AWS access/secret keys, OAuth client secrets, reCAPTCHA keys, and other API tokens. The compromise of these credentials can lead to unauthorized access to connected services, data breaches, and further lateral movement within the affected systems.

## Recommendation

*   Upgrade Grav CMS to a version beyond 2.0.0-rc.1 to address CVE-2026-44738.
*   Remove or restrict access to the `toArray` method in the Twig sandbox configuration (`system/config/security.yaml`) for the `Grav\Common\Config\Config` class to prevent unauthorized access to sensitive configuration data.
*   Deploy the Sigma rule `Detect Grav CMS Config Exfiltration via Twig` to monitor for exploitation attempts.
*   Review and rotate any exposed credentials to minimize the impact of potential compromise.
