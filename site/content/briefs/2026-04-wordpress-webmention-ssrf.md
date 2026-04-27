---
title: WordPress Webmention Plugin SSRF Vulnerability (CVE-2026-0686)
slug: 2026-04-wordpress-webmention-ssrf
description: The Webmention plugin for WordPress is vulnerable to Server-Side Request Forgery (SSRF) in versions up to 5.6.2, allowing unauthenticated attackers to make arbitrary web requests and potentially query or modify internal services.
date: "2026-04-02T08:16:27Z"
severities:
  - high
tags:
  - ssrf
  - wordpress
  - webmention
  - cve-2026-0686
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-0686
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-0686
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/08d15c46-d15f-4803-80be-90bf33335c18?source=cve
  - https://github.com/pfefferle/wordpress-webmention/blob/057223cee18a9e93b017d0f21db6ea77a7686489/includes/handler/class-mf2.php#L878
rules:
  - title: Detect Webmention SSRF Attempt via Request to Internal IP
    description: Detects potential SSRF attempts via the Webmention plugin by monitoring requests to internal IP addresses.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Webmention SSRF Attempt via Request to Localhost
    description: Detects potential SSRF attempts via the Webmention plugin by monitoring requests to localhost.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Webmention plugin for WordPress, a plugin designed to facilitate webmention communications, contains a Server-Side Request Forgery (SSRF) vulnerability identified as CVE-2026-0686. This vulnerability affects all versions of the plugin up to and including 5.6.2. The vulnerability resides within the 'MF2::parse_authorpage' function, accessible through the 'Receiver::post' function. An unauthenticated attacker can exploit this flaw to force the WordPress server to make HTTP requests to…
