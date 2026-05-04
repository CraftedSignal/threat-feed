---
title: Contact Form 7 WordPress Plugin Uncontrolled Resource Consumption Vulnerability
slug: 2026-05-contact-form-7-resource-exhaustion
description: The Contact Form 7 WordPress plugin through version 2.6.7 is vulnerable to uncontrolled resource consumption, allowing unauthenticated attackers to exhaust server memory and crash the PHP process by supplying an arbitrarily large integer value to the REST API endpoint, leading to unbounded loop execution.
date: "2026-05-04T19:16:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - wordpress
  - resource-exhaustion
  - denial-of-service
  - cve-2026-25863
vendors:
  - WordPress
products:
  - Contact Form 7 WordPress plugin
mitre_ttps:
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
cves:
  - id: CVE-2026-25863
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25863
rules:
  - title: Detect Contact Form 7 Uncontrolled Resource Consumption Attempt
    description: Detects attempts to exploit the uncontrolled resource consumption vulnerability in Contact Form 7 WordPress plugin by monitoring POST requests to the REST API with unusually large parameter values.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1499
    data_sources:
      - webserver
      - linux
  - title: Detect Excessive preg_replace() calls via Webserver Logs
    description: This rule detects a high volume of preg_replace() calls within a short time frame, which can indicate an attempt to exploit the Contact Form 7 resource consumption vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1499
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Contact Form 7 WordPress plugin, specifically versions up to 2.6.7, contains an uncontrolled resource consumption vulnerability (CVE-2026-25863) within the `Wpcf7cfMailParser` class. The `hide_hidden_mail_fields_regex_callback()` method is susceptible to unbounded loop execution due to reading an iteration count directly from user-supplied POST parameters via the REST API endpoint without proper validation. This allows unauthenticated attackers to send a large integer value, triggering multiple `preg_replace()` operations, leading to server memory exhaustion and crashing the PHP process. This vulnerability enables a denial-of-service condition, potentially impacting all websites using the vulnerable plugin.

## Attack Chain

1. An unauthenticated attacker identifies a WordPress website using Contact Form 7 plugin version 2.6.7 or earlier.
2. The attacker crafts a malicious HTTP POST request targeting the WordPress REST API endpoint.
3. The POST request includes a large integer value for the iteration count parameter, which is passed directly to the `hide_hidden_mail_fields_regex_callback()` method.
4. The `hide_hidden_mail_fields_regex_callback()` method, lacking input validation, reads the attacker-controlled integer.
5. The method initiates an unbounded loop, performing `preg_replace()` operations based on the attacker-supplied iteration count.
6. Each `preg_replace()` operation consumes server memory.
7. The excessive number of iterations rapidly exhausts available server memory.
8. The PHP process crashes due to memory exhaustion, resulting in a denial-of-service condition for the website.

## Impact

Successful exploitation of this vulnerability leads to a denial-of-service condition. Attackers can crash the PHP process on vulnerable WordPress websites by exhausting server memory. This can result in website downtime, impacting user experience and potentially leading to data loss or corruption. While the exact number of affected websites is unknown, the widespread use of Contact Form 7 makes this vulnerability a significant threat.

## Recommendation

*   Upgrade the Contact Form 7 WordPress plugin to a version greater than 2.6.7 to patch CVE-2026-25863.
*   Deploy the Sigma rule `Detect Contact Form 7 Uncontrolled Resource Consumption Attempt` to your SIEM to detect malicious POST requests targeting the WordPress REST API.
*   Monitor web server logs for abnormally large POST request sizes to the WordPress REST API endpoint, as this may indicate an attempted exploitation of CVE-2026-25863.
