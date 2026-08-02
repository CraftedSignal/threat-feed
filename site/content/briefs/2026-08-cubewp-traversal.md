---
title: Arbitrary File Read Vulnerability in CubeWP Framework
slug: 2026-08-cubewp-traversal
description: An unauthenticated directory traversal vulnerability in the CubeWP Framework plugin allows attackers to read arbitrary files by leveraging exposed AJAX nonces.
date: "2026-08-02T01:08:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-application
  - wordpress
  - vulnerability
vendors:
  - CubeWP
products:
  - CubeWP Framework (<= 1.1.30)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This is exploitable by unauthenticated attackers because the required nonce is publicly emitted into the markup.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server.
    confidence_band: high
cves:
  - id: CVE-2026-13339
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13339
---

The CubeWP Framework plugin for WordPress (versions 1.1.30 and below) contains a critical path traversal vulnerability within the 'cubewp_get_svg_content' function. This flaw allows unauthenticated attackers to read sensitive files from the underlying server filesystem. The vulnerability is highly accessible because the necessary security nonce, which should protect the AJAX endpoint, is publicly embedded in the HTML markup of pages utilizing CubeWP posts shortcodes or widgets with AJAX loading enabled. An attacker can harvest this nonce as a guest visitor and subsequently craft a malicious AJAX request to exfiltrate configuration files, credentials, or other sensitive system data. This flaw highlights the risks associated with improper nonce exposure in client-side code, which effectively nullifies the authentication mechanism intended to protect sensitive server-side functions.

## Impact

Successful exploitation allows unauthenticated attackers to perform arbitrary file reads on the web server. This can lead to the exposure of sensitive files such as 'wp-config.php', which typically contains database credentials, authentication keys, and salt values. In environments where the web server process has broader filesystem permissions, this access may facilitate further compromise or full system takeover.

## Recommendation

* Update the CubeWP Framework plugin to the latest version immediately to patch the 'cubewp_get_svg_content' function.
* Implement WAF rules to inspect and block incoming HTTP requests targeting the vulnerable AJAX endpoint with path traversal patterns (e.g., '../').
* Review web server logs for high-frequency access to sensitive configuration files originating from public IP addresses.
* Audit all WordPress plugins for similar nonce-exposure issues where security tokens are embedded in public-facing HTML.
