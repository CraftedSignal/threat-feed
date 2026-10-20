---
brief_id: brief-2026-10-20-nativechurch-path-traversal
event_id: brief-2026-10-20-nativechurch-path-traversal
revision: 1
activity_at: "2026-10-20T21:53:00Z"
title: NativeChurch WordPress theme path traversal (CVE-2014-125133)
slug: 2026-10-nativechurch-path-traversal
description: The NativeChurch WordPress theme before version 1.6.2 is vulnerable to unauthenticated path traversal via the download.php file parameter, allowing for the arbitrary download of sensitive system files.
date: "2026-10-20T21:53:00Z"
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
  validation_status: Source validated against NVD
cpes:
  - cpe:2.3:a:nativechurch_project:nativechurch:*:*:*:*:*:wordpress:*:*
tags:
  - web-application-vulnerability
  - wordpress
  - path-traversal
vendors:
  - WordPress
products:
  - NativeChurch theme (< 1.6.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The NativeChurch theme... contains a path traversal vulnerability that allows unauthenticated attackers to download arbitrary files.
    confidence_band: high
cves:
  - id: CVE-2014-125133
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2014-125133
rules:
  - title: Detect CVE-2014-125133 Exploitation - Path Traversal in download.php
    description: Detects exploitation attempts against CVE-2014-125133 where directory traversal sequences are used in the file parameter of download.php
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
    - action: Upgrade NativeChurch theme to 1.6.2 or later
      owner: IT Operations
      due: 24h
      evidence: Source states theme before 1.6.2 is vulnerable
  hunt_leads:
    - lead: Search web logs for successful (200 OK) access to download.php with traversal characters
      technique_id: T1005
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploitation allows downloading sensitive files like wp-config.php
---

The NativeChurch theme for WordPress, in versions prior to 1.6.2, contains a critical path traversal vulnerability within the 'download.php' script. This vulnerability allows an unauthenticated, remote attacker to manipulate the 'file' parameter in a GET request to access sensitive files outside of the intended directory. By utilizing directory traversal sequences (e.g., '../'), an attacker can retrieve configuration files such as 'wp-config.php', which typically contains database credentials and other security-sensitive information. This vulnerability was reportedly observed in the wild by the Shadowserver Foundation as early as October 2023. Given the ease of exploitation, organizations running this specific theme must update to version 1.6.2 or later to mitigate the risk of information disclosure and potential account takeover or database compromise.

## Attack Chain

1. Attacker performs reconnaissance to identify WordPress sites running the vulnerable NativeChurch theme.
2. Attacker crafts a malicious HTTP GET request targeting 'download.php'.
3. Attacker appends directory traversal sequences (e.g., '../../wp-config.php') to the 'file' parameter.
4. The web server process receives the crafted request and fails to sanitize the path input.
5. The application logic passes the unsanitized path to the file system API.
6. The file system retrieves the contents of the requested file (e.g., 'wp-config.php') from outside the intended base directory.
7. The server returns the sensitive file content in the HTTP response body.
8. Attacker parses the response to extract credentials or configuration data for further exploitation.

## Impact

Successful exploitation allows unauthenticated attackers to read sensitive files on the server. The primary impact is the unauthorized disclosure of 'wp-config.php', which often contains database hostnames, usernames, and passwords. This exposure can lead to full database compromise, subsequent secondary exploitation of the site, and the potential for complete site takeover.

## Recommendation

* Update the NativeChurch WordPress theme to version 1.6.2 or later immediately to patch CVE-2014-125133.
* Deploy the provided Sigma rule to web server access logs to detect and block attempts to use directory traversal sequences within the 'download.php' file parameter.
* Audit web server logs for HTTP 200 responses to 'download.php' requests that contain 'wp-config.php' in the query string.
