---
title: Smart Post Show WordPress Plugin PHP Object Injection Vulnerability
slug: 2026-04-smart-post-show-rce
description: The Smart Post Show WordPress plugin versions 3.0.12 and earlier are vulnerable to PHP Object Injection via deserialization of untrusted input in the import_shortcodes() function, potentially leading to remote code execution if a suitable POP chain is present.
date: "2026-04-14T06:17:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - php
  - object-injection
  - rce
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1219
    technique_name: Remote Access Software
cves:
  - id: CVE-2026-3017
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3017
rules:
  - title: Detect WordPress Plugin Deserialization Attempt
    description: Detects potential PHP object injection attempts via crafted requests to WordPress plugins.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
  - title: Detect Potential WordPress POP Chain Trigger
    description: Detects potential Property-Oriented Programming (POP) chain execution attempts in WordPress plugins or themes.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1219
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Smart Post Show WordPress plugin, specifically the Post Grid, Post Carousel & Slider, and List Category Posts components, contains a PHP Object Injection vulnerability. This flaw affects all versions up to and including 3.0.12. The vulnerability resides in the `import_shortcodes()` function, where the deserialization of untrusted input occurs. This vulnerability requires an authenticated attacker with administrative privileges or higher. Successful exploitation requires the presence of a suitable Property-Oriented Programming (POP) chain within another installed plugin or theme. Without a POP chain, the injected object has no immediate impact. However, with a POP chain, attackers can potentially delete arbitrary files, retrieve sensitive data, or execute arbitrary code on the server.

## Attack Chain

1. An attacker gains administrative-level access to the WordPress dashboard, either through credential compromise or vulnerability exploitation.
2. The attacker navigates to the Smart Post Show plugin settings page within the WordPress admin panel.
3. The attacker crafts a malicious payload containing a serialized PHP object designed to trigger a POP chain.
4. The attacker injects the malicious payload into the `import_shortcodes()` function, likely through a form field or file upload.
5. The `import_shortcodes()` function deserializes the attacker-controlled input, creating the malicious PHP object.
6. If a suitable POP chain exists within other installed plugins or themes, the deserialization triggers the chain.
7. The POP chain executes a series of predefined actions based on the objects and methods involved.
8. The final objective is achieved, such as deleting arbitrary files, retrieving sensitive data, or executing arbitrary code on the server.

## Impact

The PHP Object Injection vulnerability in the Smart Post Show WordPress plugin allows attackers to potentially gain remote code execution on the affected server. The impact is contingent on the existence of a POP chain within other installed plugins or themes. If successful, an attacker could potentially compromise the entire web server, leading to data breaches, defacement, or complete system takeover. Given the widespread use of WordPress and this plugin, a successful exploit could affect numerous websites across various sectors.

## Recommendation

*   Upgrade the Smart Post Show plugin to a version greater than 3.0.12 to patch CVE-2026-3017.
*   Deploy the Sigma rule "Detect WordPress Plugin Deserialization Attempt" to monitor for suspicious deserialization activity on WordPress servers.
*   Audit all installed WordPress plugins and themes for potential POP chains that could be exploited in conjunction with this vulnerability.
