---
title: MetaSlider Responsive Slider Plugin Deserialization Vulnerability (CVE-2026-39467)
slug: 2026-04-metaslider-deserialization
description: A deserialization of untrusted data vulnerability in the MetaSlider Responsive Slider plugin for WordPress (versions up to 3.106.0) allows for unauthenticated object injection, potentially leading to remote code execution.
date: "2026-04-21T10:16:29Z"
type: coverage
types:
  - coverage
severities:
  - high
tags:
  - wordpress
  - object-injection
  - deserialization
  - cve-2026-39467
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-39467
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-39467
  - https://patchstack.com/database/wordpress/plugin/ml-slider/vulnerability/wordpress-responsive-slider-by-metaslider-plugin-3-106-0-php-object-injection-vulnerability?_s_id=cve
rules:
  - title: Detect MetaSlider Object Injection Attempt
    description: Detects suspicious POST requests potentially exploiting the MetaSlider object injection vulnerability (CVE-2026-39467).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect PHP unserialize() Function Usage in WordPress Plugins
    description: Detects the usage of the `unserialize()` function within WordPress plugin files, which may indicate potential deserialization vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2026-39467 is a critical vulnerability affecting the MetaSlider Responsive Slider plugin for WordPress. Specifically, it is a Deserialization of Untrusted Data vulnerability that can lead to Object Injection. The vulnerability exists in versions up to and including 3.106.0. An attacker can exploit this vulnerability to inject arbitrary PHP objects into the application, potentially leading to remote code execution. This is possible because the plugin deserializes data without proper validation, allowing malicious actors to manipulate serialized data and inject harmful objects. The vulnerability was reported by Patchstack. Given the widespread use of WordPress and the MetaSlider plugin, this vulnerability poses a significant risk to a large number of websites.

## Attack Chain

1.  Attacker sends a crafted HTTP request to a WordPress endpoint that processes MetaSlider plugin data.
2.  The request contains a serialized PHP object designed for malicious purposes.
3.  The MetaSlider plugin deserializes the untrusted data without proper sanitization or validation using `unserialize()`.
4.  The deserialization process instantiates the malicious PHP object.
5.  The injected object executes its malicious payload, potentially writing files to the server.
6.  The attacker leverages the file write capability to plant a PHP webshell in the WordPress uploads directory.
7.  The attacker accesses the webshell via a direct HTTP request.
8.  The attacker executes arbitrary commands on the server via the webshell, gaining full control.

## Impact

Successful exploitation of CVE-2026-39467 allows an unauthenticated attacker to inject arbitrary PHP objects, leading to remote code execution on the target WordPress server. This could result in complete compromise of the website, including data theft, defacement, or further attacks on internal networks. Given the popularity of MetaSlider, potentially thousands of websites are vulnerable.

## Recommendation

*   Upgrade the MetaSlider Responsive Slider plugin to the latest version to patch CVE-2026-39467.
*   Implement the Sigma rule `Detect MetaSlider Object Injection Attempt` to detect exploitation attempts in web server logs.
*   Monitor web server logs for suspicious POST requests containing serialized PHP objects to WordPress endpoints.
