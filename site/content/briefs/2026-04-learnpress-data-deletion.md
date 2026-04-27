---
title: LearnPress WordPress Plugin Unauthorized Data Deletion Vulnerability (CVE-2026-4365)
slug: 2026-04-learnpress-data-deletion
description: The LearnPress plugin for WordPress is vulnerable to unauthorized data deletion due to a missing capability check on the `delete_question_answer()` function, allowing unauthenticated attackers to delete quiz answer options.
date: "2026-04-14T02:16:57Z"
severities:
  - critical
tags:
  - wordpress
  - plugin
  - learnpress
  - data-deletion
  - unauthorized-access
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
cves:
  - id: CVE-2026-4365
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4365
rules:
  - title: Detect LearnPress Unauthorized Data Deletion Attempt
    description: Detects attempts to exploit the LearnPress unauthorized data deletion vulnerability (CVE-2026-4365) by monitoring POST requests to admin-ajax.php with the 'delete_question_answer' action.
    platform: sigma
    severity: critical
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
      - linux
  - title: Detect LearnPress Nonce Retrieval
    description: Detects access to pages that potentially expose the LearnPress wp_rest nonce.
    platform: sigma
    severity: low
    tactics:
      - discovery
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The LearnPress plugin for WordPress, in versions up to and including 4.3.2.8, is susceptible to unauthorized data deletion. The vulnerability stems from a missing capability check on the `delete_question_answer()` function. The plugin exposes a `wp_rest` nonce in public frontend HTML, and this nonce serves as the sole security check for the `lp-load-ajax` AJAX dispatcher. As the `delete_question_answer` action lacks capability or ownership validation, unauthenticated attackers can exploit this…
