---
brief_id: brief-2026-10-20-churchope-path-traversal
event_id: brief-2026-10-20-churchope-path-traversal
revision: 1
activity_at: "2026-10-20T21:53:07Z"
title: 'ChurcHope WordPress Theme: Arbitrary file download via path traversal (CVE-2014-125134)'
slug: 2026-10-churchope-path-traversal
description: The ChurcHope theme for WordPress before version 2.2 is vulnerable to an unauthenticated path traversal attack, allowing remote adversaries to read arbitrary files from the host server.
date: "2026-10-20T21:53:07Z"
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
cpes:
  - cpe:2.3:a:churchope:churchope:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - path-traversal
  - web-application-attack
vendors:
  - WordPress
products:
  - ChurcHope (< 2.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The ChurcHope theme for WordPress before version 2.2 is vulnerable to path traversal via the file parameter in downloadlink.php.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can supply directory traversal sequences to read sensitive files like wp-config.php or /etc/passwd.
    confidence_band: high
cves:
  - id: CVE-2014-125134
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2014-125134
rules:
  - title: Detects CVE-2014-125134 Exploitation - Path Traversal in downloadlink.php
    description: Detects attempts to exploit the path traversal vulnerability in the ChurcHope WordPress theme by monitoring for traversal sequences in the file parameter.
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
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Upgrade ChurcHope theme to 2.2 or later
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects versions before 2.2.
  hunt_leads:
    - lead: Scan web access logs for requests to /wp-content/themes/churchope/lib/downloadlink.php containing ".." in the query string
      technique_id: T1190
      data_needed:
        - web_access_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Known exploitation path in the theme.
  mitigation_plan:
    - priority: immediate
      action: Upgrade ChurcHope theme to 2.2
      owner: IT Operations
      addresses: CVE-2014-125134
      evidence: Fixed in version 2.2
---

The ChurcHope theme for WordPress, prior to version 2.2, contains a critical path traversal vulnerability. This flaw resides in the 'file' parameter of the 'downloadlink.php' script located at '/wp-content/themes/churchope/lib/downloadlink.php'. An unauthenticated remote attacker can exploit this vulnerability by sending specially crafted HTTP GET requests containing directory traversal sequences (e.g., '../') to access files outside of the intended directory. Successful exploitation allows an attacker to retrieve sensitive configuration files such as 'wp-config.php', which often contains database credentials, or system files like '/etc/passwd'. This vulnerability has been subject to exploitation in the wild since October 18, 2023, as reported by the Shadowserver Foundation.

## Attack Chain

1. Attacker performs reconnaissance on the target WordPress site to identify the use of the ChurcHope theme.
2. Attacker probes the known vulnerable path: '/wp-content/themes/churchope/lib/downloadlink.php'.
3. Attacker crafts an HTTP GET request with the 'file' parameter containing traversal payloads (e.g., 'file=../../wp-config.php').
4. The web server processes the request and passes the malicious path to the PHP script.
5. The application fails to sanitize the input, allowing the script to read the requested file from the filesystem.
6. The server returns the contents of the target sensitive file in the HTTP response body.
7. Attacker parses the returned file content to extract database passwords, keys, or other sensitive configuration data.
8. Attacker uses the harvested credentials for further unauthorized access or database manipulation.

## Impact

Successful exploitation of this vulnerability leads to the disclosure of sensitive server-side information, including database credentials stored in 'wp-config.php'. This can result in complete site compromise, data exfiltration, or further unauthorized access to the underlying server environment.

## Recommendation

1. Upgrade the ChurcHope WordPress theme to version 2.2 or later immediately to patch CVE-2014-125134.
2. Implement the provided Sigma rule in your webserver monitoring environment to detect attempts to exploit this specific directory traversal vector.
3. Review web server access logs for anomalous requests to 'downloadlink.php' that include '..' sequences in the query string.
4. If an exploit is identified, immediately rotate database credentials, security keys, and salts defined in 'wp-config.php'.
