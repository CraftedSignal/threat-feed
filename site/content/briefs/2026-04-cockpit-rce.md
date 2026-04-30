---
title: Cockpit CMS Authenticated Remote Code Execution via Code Injection
slug: 2026-04-cockpit-rce
description: Cockpit CMS is vulnerable to authenticated remote code execution via PHP code injection in the /cockpit/collections/save_collection endpoint, enabling attackers with collection management privileges to execute arbitrary commands on the server.
date: "2026-04-29T20:16:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - code-injection
  - cockpit-cms
vendors:
  - agentejo
products:
  - Cockpit CMS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505
    technique_name: Server-Side Code Injection
cves:
  - id: CVE-2026-34965
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-34965
  - https://gist.github.com/thepiyushkumarshukla/64d2318518b17f529bc3ccb11fd5be90
  - https://www.vulncheck.com/advisories/cockpit-cms-authenticated-remote-code-execution-via-collections
rules:
  - title: Detect Suspicious Cockpit CMS Save Collection Activity
    description: Detects suspicious POST requests to the /cockpit/collections/save_collection endpoint, potentially indicating exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1505.003
    data_sources:
      - webserver
      - linux
  - title: Detect PHP Code Injection in Cockpit CMS Collections
    description: Detects PHP code injection attempts in the /cockpit/collections/save_collection endpoint by looking for PHP tags and functions in the request body.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
      - T1505.003
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Cockpit CMS is vulnerable to remote code execution due to insufficient input validation in the `/cockpit/collections/save_collection` endpoint. An authenticated attacker with collection management privileges can inject arbitrary PHP code into collection rules parameters. This vulnerability, identified as CVE-2026-34965, allows attackers to inject malicious PHP code through rule parameters. The injected code is then written directly to server-side PHP files and executed via the `include()` function, leading to arbitrary command execution on the underlying server. This poses a significant risk to organizations using Cockpit CMS, potentially leading to complete system compromise.

## Attack Chain

1.  Attacker authenticates to the Cockpit CMS application with valid collection management credentials.
2.  Attacker navigates to the `/cockpit/collections/save_collection` endpoint.
3.  Attacker crafts a malicious request to the `/cockpit/collections/save_collection` endpoint containing PHP code within collection rules parameters.
4.  The application saves the attacker-supplied PHP code into a PHP file on the server.
5.  The application uses the `include()` function to execute the PHP file.
6.  The injected PHP code executes arbitrary commands on the underlying server, granting the attacker control of the system.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary commands on the underlying server. This can lead to complete system compromise, including data theft, modification, or deletion. Given the high CVSS score (8.8), this vulnerability poses a critical risk, especially for internet-facing Cockpit CMS installations. Organizations in any sector using Cockpit CMS are potentially affected.

## Recommendation

*   Apply the patch or upgrade to a version of Cockpit CMS that addresses CVE-2026-34965 to remediate the vulnerability.
*   Deploy the Sigma rule `Detect Suspicious Cockpit CMS Save Collection Activity` to identify potential exploitation attempts in web server logs.
*   Monitor web server logs for POST requests to `/cockpit/collections/save_collection` with suspicious characters or PHP code in the request body, as detected by the Sigma rule `Detect PHP Code Injection in Cockpit CMS Collections`.
