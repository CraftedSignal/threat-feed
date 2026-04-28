---
title: LearnPress WordPress Plugin Unauthorized Data Deletion Vulnerability (CVE-2026-4365)
slug: 2026-04-learnpress-data-deletion
description: The LearnPress plugin for WordPress is vulnerable to unauthorized data deletion due to a missing capability check on the `delete_question_answer()` function, allowing unauthenticated attackers to delete quiz answer options.
date: "2026-04-14T02:16:57Z"
type: coverage
types:
  - coverage
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

The LearnPress plugin for WordPress, in versions up to and including 4.3.2.8, is susceptible to unauthorized data deletion. The vulnerability stems from a missing capability check on the `delete_question_answer()` function. The plugin exposes a `wp_rest` nonce in public frontend HTML, and this nonce serves as the sole security check for the `lp-load-ajax` AJAX dispatcher. As the `delete_question_answer` action lacks capability or ownership validation, unauthenticated attackers can exploit this flaw to delete arbitrary quiz answer options. This is achieved by sending a crafted POST request containing a publicly available nonce. Exploitation does not require any prior authentication.

## Attack Chain

1. An unauthenticated attacker identifies a LearnPress installation with a vulnerable version (<= 4.3.2.8).
2. The attacker accesses the public frontend of the WordPress site.
3. The attacker retrieves the `wp_rest` nonce from the `lpData` variable in the HTML source code. This nonce is used for AJAX requests.
4. The attacker crafts a POST request to the `wp-admin/admin-ajax.php` endpoint.
5. The crafted POST request includes the `action` parameter set to `delete_question_answer`.
6. The request also includes the `nonce` parameter with the value of the retrieved `wp_rest` nonce.
7. The request includes the `answer_id` parameter set to the ID of the quiz answer option to be deleted.
8. The server, lacking proper capability checks, processes the request and deletes the specified quiz answer option from the database. This results in data loss and potentially disrupts the functionality of quizzes within the LearnPress plugin.

## Impact

Successful exploitation allows unauthenticated attackers to arbitrarily delete quiz answer options within the LearnPress plugin. This can lead to data loss, disruption of quizzes, and potentially compromise the integrity of educational content. The CVSS v3.1 base score for this vulnerability is 9.1, indicating a critical severity. The number of victims and specific sectors targeted are currently unknown, but any website using the vulnerable LearnPress plugin is at risk.

## Recommendation

*   Upgrade the LearnPress plugin to a version greater than 4.3.2.8 to patch CVE-2026-4365.
*   Deploy the Sigma rule "Detect LearnPress Unauthorized Data Deletion Attempt" to your SIEM to identify potential exploitation attempts.
*   Monitor web server logs for POST requests to `wp-admin/admin-ajax.php` with the `action` parameter set to `delete_question_answer` and investigate suspicious activity.
