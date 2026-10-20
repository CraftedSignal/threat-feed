---
brief_id: brief-2026-10-20-tinymce-path-traversal
event_id: brief-2026-10-20-tinymce-path-traversal
revision: 1
activity_at: "2026-10-20T21:52:53Z"
title: 'TinyMCE Thumbnail Gallery: Path Traversal Vulnerability (CVE-2012-20002)'
slug: 2026-10-tinymce-path-traversal
description: The TinyMCE Thumbnail Gallery WordPress plugin versions prior to 1.1.0 are vulnerable to unauthenticated path traversal via the href parameter, allowing remote attackers to read arbitrary system files.
date: "2026-10-20T21:52:53Z"
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
cpes:
  - cpe:2.3:a:tinymce_thumbnail_gallery_project:tinymce_thumbnail_gallery:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - path-traversal
  - wordpress
vendors:
  - WordPress
products:
  - TinyMCE Thumbnail Gallery (< 1.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can send GET requests to /php/download-image.php with traversal sequences like ../../../../wp-config.php to retrieve database credentials and system files.
    confidence_band: high
cves:
  - id: CVE-2012-20002
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2012-20002
rules:
  - title: Detect CVE-2012-20002 Exploitation Attempt
    description: Detects path traversal attempts targeting the download-image.php script in the TinyMCE Thumbnail Gallery WordPress plugin.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1005
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade TinyMCE Thumbnail Gallery plugin to version 1.1.0
      owner: IT Operations
      due: 24h
      evidence: Vulnerability addressed in version 1.1.0
  hunt_leads:
    - lead: Identify past successful exploitation of CVE-2012-20002 in access logs
      technique_id: T1005
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation evidence was first observed by the Shadowserver Foundation on 2023-10-19.
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to 1.1.0
      owner: IT Operations
      addresses: CVE-2012-20002
      evidence: NVD advisory for CVE-2012-20002
---

The TinyMCE Thumbnail Gallery plugin for WordPress contains a path traversal vulnerability (CVE-2012-20002) in the download-image.php script. This vulnerability enables unauthenticated, remote attackers to bypass directory restrictions and access sensitive files stored on the underlying web server. By providing malicious input to the 'href' parameter, an attacker can traverse the file system to retrieve critical files such as wp-config.php, which contains database credentials and other environment secrets. This vulnerability is significant as it provides a direct path to credential exfiltration and potential secondary exploitation of the WordPress database. The Shadowserver Foundation reported observing in-the-wild exploitation of this vulnerability as early as October 2023.

## Attack Chain

1. Attacker performs reconnaissance on a target WordPress site to identify the use of the vulnerable TinyMCE Thumbnail Gallery plugin.
2. Attacker crafts an HTTP GET request targeting the path /wp-content/plugins/tinymce-thumbnail-gallery/php/download-image.php.
3. Attacker injects path traversal sequences (e.g., ../../../../) into the 'href' parameter of the request.
4. The vulnerable script fails to sanitize the 'href' input and processes the request using the provided directory traversal sequences.
5. The web server process reads the target file from the file system, such as wp-config.php.
6. The server returns the contents of the requested file in the HTTP response body to the attacker.
7. Attacker parses the returned file to extract sensitive database credentials or other configuration data.

## Impact

Successful exploitation allows unauthenticated attackers to read sensitive files on the server. If the target file is wp-config.php, the attacker gains access to database connection strings, database usernames, and passwords. This exposure facilitates unauthorized access to the application data, potentially leading to full site compromise, data exfiltration, or further persistence within the server environment.

## Recommendation

* Update the TinyMCE Thumbnail Gallery plugin to version 1.1.0 or later immediately to address CVE-2012-20002.
* Deploy the Sigma rule provided in this brief to monitor for path traversal attempts targeting the download-image.php script.
* Audit access logs for previous GET requests to /php/download-image.php containing ".." sequences, which may indicate past exploitation attempts.
