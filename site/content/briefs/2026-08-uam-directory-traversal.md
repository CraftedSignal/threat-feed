---
title: Directory Traversal Vulnerability in User Access Manager for WordPress
slug: 2026-08-uam-directory-traversal
description: An unauthenticated directory traversal vulnerability in the User Access Manager WordPress plugin (CVE-2026-18352) allows attackers to read arbitrary files by bypassing access controls via the uamgetfile parameter.
date: "2026-08-02T01:08:24Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WordPress
products:
  - User Access Manager (<= 2.3.15)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server
    confidence_band: high
cves:
  - id: CVE-2026-18352
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18352
rules:
  - title: Detects CVE-2026-18352 Exploitation - Directory Traversal in User Access Manager
    description: Detects HTTP requests attempting to use the uamgetfile parameter to perform directory traversal for file disclosure.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 1
---

The User Access Manager plugin for WordPress, in versions up to and including 2.3.15, contains a critical directory traversal vulnerability. This flaw allows unauthenticated attackers to read sensitive files from the underlying server filesystem. The vulnerability exists due to improper validation within the handling of the 'uamgetfile' parameter. Specifically, when the function attachment_url_to_postid() fails to resolve a traversal path, the plugin incorrectly falls back to a global post set by a provided 'attachment_id' parameter. This logic error allows an attacker to supply a valid public 'attachment_id' to pass initial security checks, while simultaneously supplying a traversal path in the 'uamgetfile' parameter, which the server then streams to the attacker. This impacts any WordPress environment utilizing this plugin for file access management, potentially leading to the disclosure of configuration files, database credentials, or system sensitive data.

## Attack Chain

1. The attacker performs reconnaissance to identify a target running the vulnerable version of the User Access Manager plugin.
2. The attacker identifies a valid, publicly accessible 'attachment_id' via standard WordPress enumeration or previous discovery.
3. The attacker crafts a malicious HTTP GET request targeting the plugin's file retrieval endpoint.
4. The request includes the legitimate 'attachment_id' to satisfy the plugin's security validation logic.
5. The attacker injects a directory traversal string (e.g., ../../../etc/passwd) into the 'uamgetfile' parameter.
6. The plugin's logic fails to correctly associate the traversal path with the attachment ID, improperly falling back to the valid ID while processing the traversal path.
7. The server application reads the file content from the specified traversal path and transmits it back to the attacker in the HTTP response.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary files on the web server. This can lead to the exposure of WordPress configuration files (wp-config.php), environment variables, database credentials, or other system files. Depending on the server configuration, this could provide an attacker with sufficient information to escalate privileges or gain remote code execution, impacting the integrity and confidentiality of the entire hosting environment.

## Recommendation

* Immediately update the User Access Manager plugin to a version patched against CVE-2026-18352.
* Audit webserver access logs for anomalous requests containing directory traversal sequences (e.g., "../") targeting the URL endpoints associated with the User Access Manager plugin.
* Restrict file access at the web server level (e.g., Nginx or Apache configuration) to prevent unauthorized traversal outside of the designated web root or expected directories.
* Deploy the Sigma rule below to detect attempts to exploit CVE-2026-18352 in real-time.
