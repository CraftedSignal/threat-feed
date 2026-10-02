---
title: Stored XSS in Mang Board Plugin for WordPress
slug: 2026-10-mang-board-xss
description: The Mang Board plugin for WordPress (<= 2.4.2) is vulnerable to unauthenticated Stored Cross-Site Scripting (XSS) via the 'data_type' parameter, allowing attackers to inject malicious scripts that execute in the context of user browsers.
date: "2026-10-02T08:24:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:mang_board:*:*:*:*:*:*:*:*
tags:
  - xss
  - web-vulnerability
  - wordpress
  - cve-2026-96871
vendors:
  - WordPress
products:
  - Mang Board (<= 2.4.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The vulnerability allows unauthenticated attackers to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.
    confidence_band: med
cves:
  - id: CVE-2026-96871
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-96871
rules:
  - title: Detect CVE-2026-96871 Exploitation - POST Request with Script Tags in data_type Parameter
    description: Detects potential exploitation of CVE-2026-96871 by monitoring for HTTP POST requests to the web server that contain script tags within the 'data_type' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1059.007
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Mang Board plugin to the latest version to address CVE-2026-96871.
      owner: IT Operations
      due: 48h
      evidence: Source advisory confirms vulnerability in versions <= 2.4.2
  mitigation_plan:
    - priority: immediate
      action: 'Change default board configuration: set write_level > 0 to prevent guest posting.'
      owner: IT Operations
      addresses: CVE-2026-96871
      evidence: Source states exploitation occurs on default write_level=0 settings
---

The Mang Board plugin for WordPress is affected by a Stored Cross-Site Scripting (XSS) vulnerability, tracked as CVE-2026-96871, impacting all versions up to and including 2.4.2. The vulnerability arises from insufficient input sanitization and output escaping on the 'data_type' parameter. Because the plugin defaults to guest posting ('write_level=0') and 'editor_type=N' for new boards, the attack vector is exposed to unauthenticated users out-of-the-box. Successful exploitation enables an attacker to inject arbitrary JavaScript into boards, which subsequently executes in the browsers of users viewing the content. This poses a significant risk to administrative sessions and user data within the WordPress environment.

## Attack Chain

1. Attacker identifies a WordPress site running an vulnerable version of the Mang Board plugin.
2. Attacker interacts with a publicly accessible board hosted by the plugin.
3. Attacker submits a POST request to the plugin endpoint containing a malicious payload in the 'data_type' parameter.
4. The plugin fails to sanitize the input and saves the payload directly into the database.
5. The server stores the malicious script within the board's data structure.
6. A victim user (such as an administrator or other user) browses to the compromised page.
7. The WordPress site serves the page containing the attacker's stored script.
8. The victim's browser executes the script in the context of the site, leading to session hijacking or unauthorized actions.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary JavaScript in the browsers of visitors. This can result in session hijacking, the theft of sensitive session cookies, unauthorized administrative actions performed on behalf of logged-in users, or the redirection of users to malicious websites. The vulnerability is particularly severe due to the default configuration of the plugin, which permits unauthenticated guest posting on newly created boards.

## Recommendation

Prioritize updating the Mang Board plugin to the latest available version that patches CVE-2026-96871. If patching is not immediately feasible, modify the board settings to disable 'write_level=0' (guest posting) or change the 'editor_type' to a restricted mode to limit the exposure of the vulnerable input parameter. Implement a Content Security Policy (CSP) to mitigate the impact of XSS vulnerabilities by restricting the sources from which scripts can be loaded and executed.
