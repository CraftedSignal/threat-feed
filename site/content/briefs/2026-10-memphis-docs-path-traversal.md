---
brief_id: brief-2026-10-20-memphis-docs-path-traversal
event_id: brief-2026-10-20-memphis-docs-path-traversal
revision: 1
activity_at: "2026-10-20T21:53:43Z"
title: 'Memphis Documents Library: Path traversal vulnerability (CVE-2016-20100)'
slug: 2026-10-memphis-docs-path-traversal
description: The Memphis Documents Library plugin for WordPress is vulnerable to path traversal via the mdocs-img-preview parameter, allowing unauthenticated attackers to read arbitrary files.
date: "2026-10-20T21:53:43Z"
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
  validation_status: Source-based claims verified against NVD data.
cpes:
  - cpe:2.3:a:memphis_documents_library_project:memphis_documents_library:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - vulnerability
  - web-application
  - path-traversal
products:
  - Memphis Documents Library (< 3.1.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: Unauthenticated attackers can exploit this to read arbitrary files on the host server, specifically targeting sensitive files like wp-config.php to obtain database credentials.
    confidence_band: high
cves:
  - id: CVE-2016-20100
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2016-20100
rules:
  - title: Detect CVE-2016-20100 Exploitation - Path Traversal in Memphis Documents Library
    description: Detects exploitation attempts against the Memphis Documents Library plugin by identifying directory traversal sequences in the mdocs-img-preview parameter.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1592
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Memphis Documents Library to version 3.1.6
      owner: IT Operations
      due: 24h
      evidence: CVE-2016-20100 advisory
  hunt_leads:
    - lead: Identify past GET requests to mdocs-downloads.php containing path traversal strings
      technique_id: T1592
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source notes active exploitation observed in the wild
  mitigation_plan:
    - priority: immediate
      action: Update plugin to 3.1.6
      owner: IT Operations
      addresses: CVE-2016-20100
      evidence: NVD vulnerability report
  gaps:
    - Visibility into successful file retrieval via log status codes
---

The Memphis Documents Library plugin for WordPress, in versions prior to 3.1.6, contains a path traversal vulnerability. This flaw exists within the mdocs_img_preview() function in the file mdocs-downloads.php. Unauthenticated remote attackers can leverage this vulnerability by injecting path traversal sequences into the mdocs-img-preview URL parameter. By successfully manipulating this input, attackers can access and read arbitrary files located on the web server. This vulnerability is highly critical as it permits the exfiltration of sensitive configuration files, such as wp-config.php, which often contains database credentials and other environment secrets. The Shadowserver Foundation reported observing in-the-wild exploitation of this vulnerability starting in October 2023, making patching a high priority for WordPress administrators utilizing this specific plugin.

## Attack Chain

1. Attacker performs reconnaissance to identify websites utilizing the Memphis Documents Library plugin.
2. Attacker crafts a malicious HTTP GET request targeting the mdocs_img_preview() function within mdocs-downloads.php.
3. Attacker injects path traversal sequences (e.g., ../../) into the mdocs-img-preview parameter.
4. The plugin fails to adequately sanitize the user-supplied input, allowing the directory traversal.
5. The server processes the request and retrieves the contents of the requested file outside the web root.
6. The sensitive file content, such as the site configuration, is returned in the HTTP response body to the attacker.
7. Attacker parses the exfiltrated configuration file to extract database credentials.
8. Attacker uses stolen credentials to access or modify the site database.

## Impact

Successful exploitation allows unauthenticated attackers to read any file on the underlying server that the web server user has read access to. The primary risk is the theft of the wp-config.php file, leading to the compromise of database credentials and potentially full administrative access to the WordPress application or the underlying hosting environment.

## Recommendation

* Update the Memphis Documents Library plugin to version 3.1.6 or later immediately to resolve the vulnerability.
* Audit web server access logs for requests containing suspicious path traversal patterns (e.g., ../) targeting the mdocs-img-preview parameter.
* Review database access logs and application logs for unusual activity following the potential exposure of wp-config.php.
