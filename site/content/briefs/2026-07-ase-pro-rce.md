---
title: Unauthenticated Remote Code Execution in ASE Pro WordPress Plugin
slug: 2026-07-ase-pro-rce
description: The ASE Pro WordPress plugin up to version 8.9.0 is vulnerable to unauthenticated remote code execution via insecure input handling in the recursive_html function.
date: "2026-07-30T07:19:30Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - WordPress
products:
  - Admin and Site Enhancements (ASE) Pro (<= 8.9.0)
cves:
  - id: CVE-2026-16610
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-16610
rules:
  - title: Detects CVE-2026-16610 Exploitation - RCE via cfgroup Parameter
    description: Detects suspicious POST requests to WordPress sites targeting the ASE Pro save handler with shell-metacharacters in the cfgroup parameter.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
---

The Admin and Site Enhancements (ASE) Pro plugin for WordPress, in all versions up to and including 8.9.0, contains a critical vulnerability enabling unauthenticated Remote Code Execution (RCE). The flaw exists within the recursive_html function, which processes user-provided input without adequate sanitization or authentication validation. An attacker can bypass both nonce verification and CAPTCHA mechanisms to submit malicious payloads via the cfgroup[input] parameter. This payload is subsequently passed into an eval() function call. Successful exploitation is contingent on the [post_cf_form] shortcode being present on a publicly accessible page, which allows the attacker to harvest the necessary session identifiers and nonces required to interact with the vulnerable save handler. This vulnerability represents a significant risk to WordPress site integrity as it provides an unauthenticated path for arbitrary command execution on the underlying server.

## Attack Chain

1. Attacker browses a public-facing WordPress page to identify the presence of the [post_cf_form] shortcode.
2. Attacker loads the target page to retrieve the session ID and nonce emitted by the plugin to the frontend.
3. Attacker crafts a malicious request targeting the plugin's frontend save handler.
4. Attacker omits the CAPTCHA key and includes a crafted payload within the cfgroup[input] parameter.
5. The plugin server receives the request, failing to validate the provided nonce and CAPTCHA.
6. The backend recursive_html function processes the malicious cfgroup[input] content.
7. The application executes the unsanitized input via an eval() call.
8. Arbitrary code executes on the host, granting the attacker server-level access.

## Impact

The vulnerability allows unauthenticated attackers to gain remote code execution capabilities on the hosting server. This can lead to full site compromise, sensitive data exfiltration, and the installation of persistent backdoors. Given the ubiquity of WordPress plugins, all sites utilizing ASE Pro version 8.9.0 or earlier are at immediate risk of exploitation if the [post_cf_form] shortcode is exposed.

## Recommendation

1. Update the ASE Pro plugin to the latest version immediately to remediate CVE-2026-16610.
2. Audit all public-facing pages for the presence of the [post_cf_form] shortcode and remove it if it is not strictly required.
3. Deploy the provided web server detection rules to monitor for suspicious POST requests containing common PHP command execution patterns.
4. Monitor web server logs for HTTP requests directed to the plugin's save handler endpoint that lack legitimate CAPTCHA or nonce headers.
