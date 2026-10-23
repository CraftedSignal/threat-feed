---
brief_id: brief-2026-10-23-music-store-traversal
event_id: brief-2026-10-23-music-store-traversal
revision: 1
activity_at: "2026-10-23T06:47:22Z"
title: 'The Music Store WordPress Plugin: Directory traversal vulnerability (CVE-2026-115497)'
slug: 2026-10-music-store-traversal
description: The Music Store WordPress plugin version 1.4.7 and earlier contains a directory traversal vulnerability in the f parameter, allowing unauthenticated attackers with a valid purchase_id to read arbitrary files from the server.
date: "2026-10-23T06:47:22Z"
type: advisory
types:
  - advisory
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
cpes:
  - cpe:2.3:a:the_music_store_project:the_music_store:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - wordpress
  - cve-2026-115497
  - file-read
  - directory-traversal
products:
  - The Music Store – WordPress eCommerce (<= 1.4.7)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server
    confidence_band: high
cves:
  - id: CVE-2026-115497
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-115497
rules:
  - title: Detects CVE-2026-115497 Exploitation - Directory Traversal in The Music Store Plugin
    description: Detects attempts to use directory traversal sequences in the "f" parameter of the The Music Store WordPress plugin.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy Sigma rule to detect directory traversal attempts targeting the Music Store plugin
      owner: Detection Engineering
      due: 24h
      evidence: Source describes directory traversal vulnerability via f parameter
  mitigation_plan:
    - priority: immediate
      action: Update The Music Store plugin to the latest secure version once released
      owner: IT Operations
      addresses: CVE-2026-115497
      evidence: Vulnerability exists in versions up to 1.4.7
---

The Music Store eCommerce plugin for WordPress contains a directory traversal vulnerability (CVE-2026-115497). An unauthenticated attacker can exploit this flaw by manipulating the 'f' parameter in requests to the plugin. Successful exploitation requires the attacker to possess a valid 'purchase_id' token, which can be acquired through legitimate plugin usage. This vulnerability allows for the unauthorized reading of arbitrary files on the underlying server, potentially exposing sensitive system or application configuration files.

## Impact

Successful exploitation allows unauthenticated remote attackers to read arbitrary files from the server's filesystem, leading to potential information disclosure of sensitive credentials, configuration files, or other private data stored on the web server.

## Recommendation

- Update the "The Music Store - WordPress eCommerce" plugin to the version containing the patch for CVE-2026-115497 once available from the vendor.
- Implement web application firewall (WAF) rules to inspect the 'f' parameter for directory traversal sequences (e.g., ../, ..\/) in HTTP requests targeting this plugin.
- Monitor web server access logs for anomalous requests to the plugin containing directory traversal patterns in query parameters.
