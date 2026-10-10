---
title: Arbitrary File Read Vulnerability in Divi Plus Plugin
slug: 2026-10-divi-plus-file-read
description: The Divi Plus WordPress plugin contains an arbitrary file read vulnerability (CVE-2026-91136) in the SVG animator REST endpoint that allows unauthenticated attackers to exfiltrate sensitive server files.
date: "2026-10-10T09:52:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:elicus:divi_plus:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - vulnerability
  - web-application
vendors:
  - Elicus
products:
  - Divi Plus (<= 2.4.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to read arbitrary files on the affected site's server.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1505.002
    technique_name: 'Server Software Component: Web Shell'
    evidence: This makes it possible for unauthenticated attackers to read arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-91136
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-91136
rules:
  - title: Detect CVE-2026-91136 Exploitation - Arbitrary File Read in Divi Plus
    description: Detects exploitation of the Divi Plus svg-animator endpoint by looking for path traversal patterns or file stream wrappers in the svg_image parameter.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Divi Plus to the version remediating CVE-2026-91136
      owner: IT Operations
      due: 48h
      evidence: Plugin version 2.4.0 is vulnerable
  mitigation_plan:
    - priority: immediate
      action: Block access to /wp-json/elicus/v1/dipl-modules/svg-animator via WAF if patching is delayed
      owner: SOC
      addresses: CVE-2026-91136
      evidence: Endpoint is unauthenticated
---

The Divi Plus plugin for WordPress, in versions up to and including 2.4.0, is susceptible to an arbitrary file read vulnerability (CVE-2026-91136). The flaw resides in the /wp-json/elicus/v1/dipl-modules/svg-animator REST API endpoint, specifically within the 'svg_image' parameter. The plugin's permission callback, SVGAnimatorController::index_permission, fails to enforce authentication, allowing unauthenticated requests to reach the vulnerable code. Input validation is insufficient; the plugin utilizes sanitize_text_field() and esc_html(), which do not prevent the use of filesystem paths, the file:// stream wrapper, or remote URLs. These inputs are subsequently passed to file_get_contents() or a fallback wp_remote_get(), with the resulting file contents returned in the 'html' field of the JSON response. This vulnerability poses a significant risk as it allows attackers to read sensitive configuration files, potentially facilitating further exploitation and remote code execution.

## Impact

Successful exploitation allows an unauthenticated attacker to read arbitrary files from the WordPress server filesystem. This can lead to the exposure of sensitive data such as wp-config.php, database credentials, environment variables, and site keys, which can be leveraged to achieve full site takeover or remote code execution.

## Recommendation

* Immediately update the Divi Plus plugin to a version patched against CVE-2026-91136.
* Monitor web server logs for HTTP requests directed to '/wp-json/elicus/v1/dipl-modules/svg-animator' with parameters containing path traversal sequences or stream wrappers (e.g., file://, /etc/passwd).
* If an update is not immediately feasible, disable the affected REST endpoint via a web application firewall (WAF) rule blocking access to the specific API URI.
