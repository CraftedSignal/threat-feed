---
title: wpForo Forum Plugin Arbitrary File Deletion Vulnerability (CVE-2026-5809)
slug: 2026-04-wpforo-file-deletion
description: The wpForo Forum plugin for WordPress is vulnerable to arbitrary file deletion due to a logic flaw that allows authenticated users to delete arbitrary files writable by the PHP process by manipulating post metadata.
date: "2026-04-11T08:16:05Z"
severities:
  - critical
tags:
  - wordpress
  - file-deletion
  - plugin
  - CVE-2026-5809
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-5809
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-5809
rules:
  - title: Detect wpForo Arbitrary File Deletion Attempt
    description: Detects attempts to exploit the wpForo arbitrary file deletion vulnerability by monitoring for POST requests containing the wpftcf_delete parameter and suspicious file paths.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: Detect wpForo Malicious File Path in Post Meta
    description: Detects attempts to inject malicious file paths into wpForo post meta data via the data[body][fileurl] parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The wpForo Forum plugin, a popular WordPress plugin, is susceptible to an arbitrary file deletion vulnerability (CVE-2026-5809) affecting versions up to and including 3.0.2. The vulnerability stems from insufficient validation of user-supplied data within the `topic_add()` and `topic_edit()` action handlers. Specifically, the plugin improperly handles array values in the `$_REQUEST` data, storing them as postmeta without proper filtering. An authenticated attacker (subscriber-level or higher)…
