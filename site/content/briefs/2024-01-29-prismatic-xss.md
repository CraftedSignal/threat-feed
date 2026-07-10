---
title: Prismatic WordPress Plugin Stored XSS Vulnerability
slug: 2024-01-29-prismatic-xss
description: The Prismatic plugin for WordPress versions 3.7.3 and earlier is vulnerable to stored cross-site scripting (XSS) via the 'prismatic_encoded' pseudo-shortcode, allowing unauthenticated attackers to inject arbitrary web scripts into pages.
date: "2024-01-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - xss
  - plugin
  - prismatic
vendors:
  - Prismatic
  - WordPress
products:
  - Prismatic plugin
  - WordPress
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1055
    technique_name: Process Injection
cves:
  - id: CVE-2026-3876
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-3876
rules:
  - title: Detect Prismatic WordPress Plugin XSS Attempt
    description: Detects potential attempts to exploit the Prismatic WordPress plugin XSS vulnerability by identifying comments containing the 'prismatic_encoded' shortcode with suspicious content.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1055
    data_sources:
      - webserver
      - linux
  - title: Detect WordPress POST with script tag
    description: Detects WordPress POST requests containing a script tag in the query string, potentially indicative of XSS attempts.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1055
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Prismatic plugin, a WordPress extension, is susceptible to a stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-3876. This flaw exists in all versions up to and including 3.7.3. The vulnerability arises due to inadequate input sanitization and output escaping of user-supplied attributes within the 'prismatic_decode' function, which handles the 'prismatic_encoded' pseudo-shortcode. Exploitation occurs when an unauthenticated attacker injects malicious web scripts into a page by submitting a comment containing a specially crafted 'prismatic_encoded' pseudo-shortcode. Successful exploitation allows the attacker to execute arbitrary JavaScript code in the context of a user's browser when they view the compromised page. This could lead to account compromise, data theft, or other malicious actions.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress site using the vulnerable Prismatic plugin (version <= 3.7.3).
2.  The attacker crafts a malicious comment containing the `prismatic_encoded` pseudo-shortcode. This shortcode includes a payload designed to execute arbitrary JavaScript in the browser. The `prismatic_encoded` value is crafted to bypass weak sanitization.
3.  The attacker submits the comment to a blog post or page on the target WordPress site.
4.  The WordPress application stores the malicious comment, including the embedded XSS payload, in the database.
5.  A legitimate user visits the blog post or page where the malicious comment was posted.
6.  The WordPress application renders the page, processing the stored comment and executing the malicious JavaScript code embedded within the `prismatic_encoded` shortcode due to the insufficient output escaping.
7.  The attacker's JavaScript code executes in the user's browser, potentially stealing cookies, redirecting the user to a malicious site, or performing other unauthorized actions.

## Impact

Successful exploitation of this stored XSS vulnerability (CVE-2026-3876) allows unauthenticated attackers to inject arbitrary web scripts into WordPress pages. This can lead to a range of malicious outcomes, including account takeover, defacement of the website, redirection of users to phishing sites, and theft of sensitive information. The impact is magnified by the fact that the XSS is stored, meaning that the malicious script will be executed every time a user visits the affected page until the malicious comment is removed or the vulnerability is patched. While the number of affected sites is unknown, any WordPress installation running a vulnerable version of the Prismatic plugin is at risk.

## Recommendation

*   Upgrade the Prismatic plugin to the latest version (greater than 3.7.3) to patch the vulnerability (CVE-2026-3876).
*   Implement input validation and output encoding/escaping for all user-supplied data, especially within WordPress plugins, to prevent XSS vulnerabilities.
*   Deploy the Sigma rule `Detect Prismatic WordPress Plugin XSS Attempt` to identify attempts to exploit the vulnerability through malicious comments containing the `prismatic_encoded` shortcode.
*   Monitor WordPress logs (category `webserver`, product `linux`) for suspicious POST requests to `/wp-comments-post.php` containing the `prismatic_encoded` string.
