---
title: WordPress Kirki Plugin Arbitrary File Deletion (CVE-2026-8073)
slug: 2026-05-kirki-file-deletion
description: The Kirki plugin for WordPress is vulnerable to arbitrary file deletion via CVE-2026-8073 due to insufficient file path validation and a missing capability check in the 'downloadZIP' function, allowing unauthenticated attackers to delete files within the WordPress uploads directory.
date: "2026-05-19T19:18:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - wordpress
  - file-deletion
vendors:
  - WordPress
products:
  - Kirki – Freeform Page Builder, Website Builder & Customizer plugin
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-8073
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8073
  - https://www.wordfence.com/threat-intel/vulnerabilities/id/b073edd0-3f40-423e-976e-996b29caf66e?source=cve
  - https://plugins.trac.wordpress.org/browser/kirki/tags/6.0.1/includes/API.php#L60
  - https://plugins.trac.wordpress.org/changeset/3535640/kirki/trunk/includes/API.php
rules:
  - title: Detect CVE-2026-8073 Exploitation — Kirki Arbitrary File Deletion
    description: Detects CVE-2026-8073 exploitation attempt — Path traversal in Kirki plugin's downloadZIP function to delete arbitrary files.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
  - title: Detect CVE-2026-8073 Exploitation — Kirki Arbitrary File Deletion (POST Request)
    description: Detects CVE-2026-8073 exploitation attempt via POST request — Path traversal in Kirki plugin's downloadZIP function to delete arbitrary files.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
rules_count: 2
---

The Kirki – Freeform Page Builder, Website Builder & Customizer plugin for WordPress, versions 6.0.6 and earlier, contains an arbitrary file deletion vulnerability (CVE-2026-8073). This flaw stems from a lack of sufficient file path validation and the absence of a capability check within the 'downloadZIP' function. Unauthenticated attackers can exploit this to read and delete arbitrary files, provided they are located within the WordPress uploads base directory. This poses a significant risk to WordPress sites using the Kirki plugin, potentially leading to data loss and service disruption.

## Attack Chain

1.  An unauthenticated attacker identifies a WordPress site using a vulnerable version of the Kirki plugin (<= 6.0.6).
2.  The attacker crafts a malicious HTTP request targeting the 'downloadZIP' function.
3.  The request contains a manipulated file path, bypassing insufficient validation, to point to a target file within the WordPress uploads directory.
4.  The 'downloadZIP' function, lacking capability checks, processes the request without proper authorization.
5.  The attacker triggers file deletion within the WordPress uploads directory using path traversal.
6.  The targeted file is deleted from the server.
7.  The attacker can repeat this process to delete multiple files within the uploads directory.
8.  The attacker achieves arbitrary file deletion, potentially leading to data loss or site defacement.

## Impact

Successful exploitation of CVE-2026-8073 allows unauthenticated attackers to delete arbitrary files within the WordPress uploads directory. This can lead to significant data loss, site defacement, or disruption of services. The vulnerability affects all WordPress sites using Kirki plugin versions 6.0.6 and earlier. A CVSS v3.1 score of 7.5 indicates a high severity.

## Recommendation

*   Upgrade the Kirki plugin to the latest version to patch CVE-2026-8073.
*   Deploy the Sigma rule "Detect CVE-2026-8073 Exploitation — Kirki Arbitrary File Deletion" to your SIEM and tune for your environment.
*   Monitor web server logs for suspicious requests to 'downloadZIP' function with path traversal attempts, using the log source detailed in the provided Sigma rules.
