---
title: WordPress Webmention Plugin SSRF Vulnerability (CVE-2026-0686)
slug: 2026-04-wordpress-webmention-ssrf
description: The Webmention plugin for WordPress is vulnerable to Server-Side Request Forgery (SSRF) in versions up to 5.6.2, allowing unauthenticated attackers to make arbitrary web requests and potentially query or modify internal services.
date: "2026-04-02T08:16:27Z"
severities:
  - high
type: advisory
types:
  - advisory
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

The Webmention plugin for WordPress, a plugin designed to facilitate webmention communications, contains a Server-Side Request Forgery (SSRF) vulnerability identified as CVE-2026-0686. This vulnerability affects all versions of the plugin up to and including 5.6.2. The vulnerability resides within the 'MF2::parse_authorpage' function, accessible through the 'Receiver::post' function. An unauthenticated attacker can exploit this flaw to force the WordPress server to make HTTP requests to arbitrary external or internal locations. This can be leveraged to gather sensitive information from internal services, bypass firewalls, or potentially modify data depending on the accessibility of internal resources. The vulnerable code was present as of April 2026 in the version 5.6.2 branch.

## Attack Chain

1.  An unauthenticated attacker crafts a malicious webmention request targeting a WordPress site running the vulnerable Webmention plugin.
2.  The WordPress site receives the webmention request and processes it using the 'Receiver::post' function.
3.  The 'Receiver::post' function calls the 'MF2::parse_authorpage' function to parse the author page URL specified in the webmention request.
4.  The 'MF2::parse_authorpage' function, due to lack of proper validation, makes an HTTP request to an attacker-controlled or internal URL specified within the webmention data.
5.  The WordPress server initiates a connection to the specified URL, potentially bypassing firewall restrictions or accessing internal services not directly exposed to the internet.
6.  The response from the targeted URL is processed by the plugin, potentially revealing information about the internal network or services.
7.  Depending on the targeted internal service and the attacker's crafted request, the attacker might be able to modify data or execute commands.
8.  Successful exploitation leads to information disclosure, internal service compromise, or potential remote code execution depending on the vulnerable internal service.

## Impact

Successful exploitation of CVE-2026-0686 allows unauthenticated attackers to perform Server-Side Request Forgery attacks against WordPress sites utilizing the Webmention plugin. This can lead to the exposure of sensitive information from internal services, such as configuration files or database credentials. Furthermore, attackers could potentially leverage this vulnerability to interact with and potentially compromise other internal systems that are not directly accessible from the internet, leading to a full compromise of the affected network. While the exact number of affected WordPress installations is unknown, the widespread use of the Webmention plugin makes this a significant risk.

## Recommendation

*   Upgrade the Webmention plugin to a version higher than 5.6.2 to patch CVE-2026-0686.
*   Deploy the Sigma rule "Detect Webmention SSRF Attempt via Request to Internal IP" to identify exploitation attempts in web server logs.
*   Monitor web server logs for unusual outbound connections originating from the WordPress server to internal IP addresses.
*   Implement network segmentation to limit the impact of potential SSRF attacks, restricting access from the WordPress server to only necessary internal services.
