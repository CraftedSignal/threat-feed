---
title: Brizy WordPress Plugin Unauthenticated Stored XSS Vulnerability
slug: 2024-01-brizy-xss
description: The Brizy – Page Builder plugin for WordPress is vulnerable to Unauthenticated Stored Cross-Site Scripting (XSS) in versions up to and including 2.8.11, allowing unauthenticated attackers to inject arbitrary web scripts that execute when an administrator views the form Leads page due to missing nonce verification and improper handling of file upload fields.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - xss
  - unauthenticated
vendors:
  - WordPress
products:
  - Brizy – Page Builder plugin <= 2.8.11
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-5324
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5324
rules:
  - title: Detect Brizy WordPress Plugin XSS Attempt via HTTP Request
    description: Detects attempts to exploit the Brizy WordPress plugin XSS vulnerability by looking for specific parameters in HTTP requests.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect HTML Entity Encoding Reversal in Web Server Logs
    description: Detects potential XSS exploits where HTML entities are decoded and used in URI queries.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Brizy – Page Builder plugin for WordPress, a popular tool for designing website pages, contains a critical vulnerability that allows unauthenticated users to inject malicious JavaScript code. Specifically, versions up to and including 2.8.11 are affected. This vulnerability arises from a combination of factors, including the lack of nonce verification for form submissions from non-logged-in users, inadequate handling of FileUpload fields when no file is actually uploaded, and the unintended reversal of security encoding through `html_entity_decode()` before outputting data. This allows attackers to inject arbitrary web scripts that execute in the context of a logged-in administrator viewing the form's "Leads" page, potentially leading to account takeover, data theft, or further compromise of the WordPress site.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious payload containing JavaScript code.
2.  The attacker submits this payload through a Brizy form on the WordPress site, exploiting the missing nonce verification in the `submit_form()` function.
3.  The `handleFileTypeFields()` function fails to properly sanitize or overwrite the attacker-supplied values when no file is attached to the form submission.
4.  The injected payload, now stored in the WordPress database, bypasses initial `htmlentities()` encoding due to later `html_entity_decode()`.
5.  An administrator logs into the WordPress dashboard and navigates to the "Leads" page to view form submissions.
6.  The form-data.php template retrieves the stored malicious payload from the database.
7.  The payload is outputted directly within the `href` attribute of an HTML element without proper escaping using `esc_url()`.
8.  The injected JavaScript code executes within the administrator's browser, potentially performing actions such as stealing cookies or redirecting the administrator to a malicious site.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to execute arbitrary JavaScript code in the context of a logged-in administrator's browser. This could lead to a full compromise of the WordPress site, including the ability to create new administrative accounts, modify existing content, inject malware into the site's pages, or steal sensitive data. The impact is significant, as it requires no user interaction beyond an administrator viewing the form submissions within the Brizy plugin.

## Recommendation

*   Upgrade the Brizy – Page Builder plugin to the latest version to patch CVE-2026-5324.
*   Deploy the Sigma rule "Detect Brizy WordPress Plugin XSS Attempt via HTTP Request" to identify potential exploitation attempts in web server logs.
*   Review the `form-data.php` template and implement proper output escaping using `esc_url()` for all user-supplied data to prevent XSS, as mentioned in the vulnerability description.
