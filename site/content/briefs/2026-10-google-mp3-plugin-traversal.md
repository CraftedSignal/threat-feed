---
title: Unauthenticated Arbitrary File Read in Google MP3 Audio Player Plugin
slug: 2026-10-google-mp3-plugin-traversal
description: The CodeArt Google MP3 Audio Player plugin for WordPress contains an unauthenticated path-traversal vulnerability in direct_download.php that allows remote attackers to read sensitive configuration files.
date: "2026-10-02T20:26:38Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:codeart:google_mp3_audio_player:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - plugin
  - path-traversal
  - arbitrary-file-read
vendors:
  - CodeArt
products:
  - Google MP3 Audio Player (<= 1.0.11)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Google MP3 Audio Player plugin contains an unauthenticated arbitrary file read vulnerability that allows remote attackers to retrieve sensitive files.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Attackers can request paths ../../wp-config.php without authentication to download configuration files.
    confidence_band: high
cves:
  - id: CVE-2014-125130
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2014-125130
rules:
  - title: Detect CVE-2014-125130 Exploitation - Path Traversal in direct_download.php
    description: Detects exploitation attempts against CVE-2014-125130 by identifying path traversal sequences in requests to direct_download.php.
    platform: sigma
    severity: high
    tactics:
      - initial_access
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
    - action: Review web server logs for requests targeting direct_download.php with path traversal characters.
      owner: SOC
      due: 24h
      evidence: Active exploitation observed since 2023-10-19.
  mitigation_plan:
    - priority: immediate
      action: Disable or remove the Google MP3 Audio Player plugin until an update is available.
      owner: IT Operations
      addresses: CVE-2014-125130
      evidence: Plugin contains unauthenticated file read vulnerability.
---

The CodeArt Google MP3 Audio Player plugin (google-mp3-audio-player) for WordPress, in versions through 1.0.11, is susceptible to an unauthenticated arbitrary file read vulnerability. The flaw exists within the `direct_download.php` script, which fails to properly sanitize user-supplied input provided via the `file` parameter. By crafting a request containing path-traversal sequences, a remote, unauthenticated attacker can escape the intended directory and access arbitrary files on the underlying web server.

This vulnerability is particularly critical because it allows for the retrieval of `wp-config.php`, which typically contains sensitive database credentials, authentication unique keys, and salts. Access to these files provides the attacker with the necessary information to gain deeper access to the WordPress environment or potentially perform remote code execution if the database is accessible. Active exploitation of this vulnerability has been observed since October 2023, as reported by the Shadowserver Foundation.

## Impact

Successful exploitation allows an unauthenticated attacker to read arbitrary files from the server's file system. This often leads to the compromise of the `wp-config.php` file, resulting in the exposure of database credentials and cryptographic secrets. An attacker possessing these credentials can gain full administrative control over the WordPress application, leading to complete site compromise, data theft, or the installation of malicious persistent backdoors.

## Recommendation

1. Patch immediately by updating the Google MP3 Audio Player plugin to a version beyond 1.0.11, if available.
2. If an update is not available, remove the plugin entirely or restrict access to `direct_download.php` at the web server level.
3. Deploy the provided Sigma rule to detect attempts to access `direct_download.php` with path-traversal sequences in the `file` parameter.
4. Audit server logs for requests containing suspicious sequences like `../` directed at this plugin endpoint.
