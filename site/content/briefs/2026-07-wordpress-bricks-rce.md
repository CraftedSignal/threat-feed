---
title: WordPress Bricks Builder Theme - Unauthenticated RCE (CVE-2024-25600)
slug: 2026-07-wordpress-bricks-rce
description: An unauthenticated Remote Code Execution (RCE) vulnerability (CVE-2024-25600) exists in the WordPress Bricks Builder Theme up to version 1.9.6, allowing attackers to exploit the 'render_element' endpoint by first extracting a nonce from the page source, then injecting PHP code to execute arbitrary operating system commands on the underlying web server, with a public exploit now available.
date: "2026-07-07T13:26:28Z"
lastmod: "2026-07-16T21:00:52Z"
type: advisory
types:
  - advisory
severities:
  - high
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=4D839E55-13BB-57EF-8F41-540284E6BECC&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - rce
  - webapps
  - exploit-db
  - cve
vendors:
  - Bricks Builder
  - Bricks
products:
  - Bricks Builder Theme < 1.9.7
  - Bricks Builder (<= 1.9.6)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated RCE vulnerability in Bricks Builder theme's render_element endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Executes arbitrary commands on vulnerable WordPress installations... `<?php throw new Exception(`{command}`);?>`
    confidence_band: high
cves:
  - id: CVE-2024-25600
    cvss: 10
    epss: 0.88234
references:
  - https://www.exploit-db.com/exploits/52619
  - https://sploitus.com/exploit?id=4D839E55-13BB-57EF-8F41-540284E6BECC&utm_source=rss&utm_medium=rss
iocs:
  - type: url
    value: https://sploitus.com/exploit?id=4D839E55-13BB-57EF-8F41-540284E6BECC
  - type: url
    value: https://github.com/CerberusMrXi/WP-Bricks-Exploit-CVE-2024-25600.git
  - type: url_path
    value: /wp-json/bricks/v1/render_element
  - type: url_path
    value: /?rest_route=/bricks/v1/render_element
ioc_counts:
  url: 2
  url_path: 2
rules:
  - title: Detect CVE-2024-25600 Exploitation - Bricks Builder RCE
    description: Detects exploitation attempts for CVE-2024-25600, an unauthenticated RCE vulnerability in WordPress Bricks Builder Theme via specific API endpoints and PHP command injection.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-07-16T21:00:52Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=4D839E55-13BB-57EF-8F41-540284E6BECC&utm_source=rss&utm_medium=rss
---

A critical unauthenticated Remote Code Execution (RCE) vulnerability, tracked as CVE-2024-25600, has been disclosed and publicly exploited in the WordPress Bricks Builder Theme versions up to and including 1.9.6. Attackers can leverage the `render_element` endpoint, which is part of the theme's AJAX functionality, to execute arbitrary operating system commands on the compromised WordPress server. This exploitation begins with an initial request to retrieve a valid nonce from the page source, which is then used in a subsequent crafted POST request to the vulnerable endpoint. The availability of a working public exploit, identified as EDB-52619 on Exploit-DB, significantly elevates the risk, making unpatched WordPress installations using Bricks Builder Theme prime targets for immediate compromise by a broad range of malicious actors.

## Attack Chain

1.  **Initial Access**: An unauthenticated attacker targets a public-facing WordPress instance running the vulnerable Bricks Builder Theme (version <= 1.9.6).
2.  **Information Gathering**: The attacker sends a GET request to the target WordPress site to retrieve the HTML source code of any page.
3.  **Defense Evasion (Nonce Extraction)**: The attacker parses the HTML response to locate a `<script>` tag with the ID `bricks-scripts-js-extra` and extracts the `nonce` value from its content using a regular expression.
4.  **Execution - PHP Code Injection**: The attacker crafts a malicious JSON payload containing the extracted `nonce` and PHP code designed to execute arbitrary OS commands using PHP's backtick operator (e.g., `` `command` ``).
5.  **Exploitation Request**: A POST request is sent to either `/wp-json/bricks/v1/render_element` or `/?rest_route=/bricks/v1/render_element` with the crafted JSON payload, triggering the RCE.
6.  **Command and Control**: Upon successful exploitation, the attacker achieves remote code execution and can establish an interactive shell or execute further commands to maintain persistence, exfiltrate data, or deploy additional malware.

## Impact

Successful exploitation of CVE-2024-25600 results in unauthenticated remote code execution on the underlying server hosting the WordPress installation. This grants attackers full control over the compromised web server, allowing them to steal sensitive data, deface the website, inject malware, pivot to other systems within the network, or establish persistent backdoors. Given the widespread use of WordPress and its themes, the potential number of vulnerable instances is high, making this a critical threat to organizations relying on Bricks Builder Theme.

## Recommendation

*   Immediately update the WordPress Bricks Builder Theme to a patched version (1.9.7 or newer) to remediate CVE-2024-25600.
*   Deploy the `Detect CVE-2024-25600 Exploitation - Bricks Builder RCE` Sigma rule to your SIEM and tune for your environment to identify exploitation attempts.
*   Monitor `webserver` logs for suspicious POST requests containing PHP code injection patterns to the `/wp-json/bricks/v1/render_element` or `/?rest_route=/bricks/v1/render_element` endpoints.
