---
brief_id: brief-2026-10-20-aspose-doc-exporter-traversal
event_id: brief-2026-10-20-aspose-doc-exporter-traversal
revision: 1
activity_at: "2026-10-20T21:53:15Z"
title: 'Aspose Doc Exporter: Path traversal vulnerability (CVE-2015-20123)'
slug: 2026-10-aspose-doc-exporter-traversal
description: The Aspose Doc Exporter WordPress plugin before version 2.0 contains a path traversal vulnerability that allows unauthenticated attackers to read arbitrary files from the server.
date: "2026-10-20T21:53:15Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Ready for deployment
cpes:
  - cpe:2.3:a:aspose:aspose_doc_exporter:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - path-traversal
  - web-exploitation
vendors:
  - Aspose
products:
  - Aspose Doc Exporter (< 2.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Aspose Doc Exporter plugin for WordPress before version 2.0 is vulnerable to path traversal via the file parameter in aspose_doc_exporter_download.php.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Unauthenticated attackers can exploit this to read arbitrary files from the server, such as wp-config.php, potentially exposing sensitive database credentials.
    confidence_band: high
cves:
  - id: CVE-2015-20123
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2015-20123
rules:
  - title: Detect CVE-2015-20123 Exploitation - Path Traversal in Aspose Doc Exporter
    description: Detects exploitation attempts against the Aspose Doc Exporter WordPress plugin by looking for path traversal sequences in the file parameter of aspose_doc_exporter_download.php
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade all WordPress instances running Aspose Doc Exporter to version 2.0 or later
      owner: IT Operations
      due: 48h
      evidence: Vulnerability affects all versions before 2.0
  hunt_leads:
    - lead: Search web server logs for HTTP requests to aspose_doc_exporter_download.php containing dots or path segments
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source notes exploitation observed in the wild
  mitigation_plan:
    - priority: immediate
      action: Update vulnerable plugin to 2.0
      owner: IT Operations
      addresses: CVE-2015-20123
      evidence: Vendor patch level
---

The Aspose Doc Exporter plugin for WordPress, specifically versions prior to 2.0, contains a path traversal vulnerability originating from improper input sanitization in the `readfile()` function. The flaw allows unauthenticated remote attackers to bypass directory restrictions and access arbitrary files on the web server. By crafting malicious GET requests to the `aspose_doc_exporter_download.php` script and manipulating the `file` parameter, an attacker can traverse the directory structure to retrieve sensitive configuration files, such as `wp-config.php`. Access to this file typically results in the exposure of database credentials, which can lead to full site takeover or further internal network compromise. This vulnerability has been subject to active exploitation in the wild since at least October 2023.

## Attack Chain

1. Attacker performs reconnaissance to identify sites running the vulnerable Aspose Doc Exporter WordPress plugin.
2. Attacker crafts an HTTP GET request targeting the `aspose_doc_exporter_download.php` endpoint.
3. Attacker appends a malicious path traversal string to the `file` parameter (e.g., `../../../wp-config.php`).
4. The web server processes the request and executes the `readfile()` function with the unsanitized user input.
5. The application returns the contents of the target system file in the HTTP response body.
6. Attacker parses the response to extract cleartext database credentials or other sensitive configuration data.
7. Attacker uses stolen credentials to access the backend database or authenticates as a high-privileged user.
8. Attacker achieves unauthorized access to the application data or proceeds with further lateral movement.

## Impact

Successful exploitation allows unauthenticated attackers to read sensitive server-side files. For WordPress environments, the most common target is `wp-config.php`, which contains hardcoded database host, username, and password information. This exposure enables attackers to modify the database, inject malicious content into the site, or exfiltrate customer data, leading to total site compromise.

## Recommendation

* Update the Aspose Doc Exporter plugin to version 2.0 or later immediately to apply the vendor-provided patch.
* Monitor web server logs for requests to `aspose_doc_exporter_download.php` containing directory traversal patterns like `../`, `..%2f`, or `..%5c`.
* Use the Sigma rule provided below to detect exploitation attempts targeting this specific endpoint.
