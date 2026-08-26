---
title: CVE-2026-15990 Directory Traversal in Formidable Charts Plugin
slug: 2026-08-formidable-charts-traversal
description: The Formidable Charts WordPress plugin is vulnerable to an unauthenticated directory traversal attack via the 'frm_graph' parameter, enabling arbitrary file read on the underlying server.
date: "2026-08-26T16:21:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - wordpress
  - web-application
vendors:
  - Formidable Forms
products:
  - Formidable Charts
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Formidable Charts plugin for WordPress is vulnerable to a directory traversal attack via the 'frm_graph' parameter, allowing unauthenticated attackers to read arbitrary files on the server.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Successful exploitation allows for the reading of arbitrary files from the server filesystem.
    confidence_band: high
cves:
  - id: CVE-2026-15990
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15990
rules:
  - title: Detects CVE-2026-15990 Exploitation - Directory Traversal via frm_graph
    description: Detects attempts to exploit CVE-2026-15990 by identifying directory traversal sequences within the frm_graph parameter of web requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Formidable Charts plugin to version > 2.0.1
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability entry
    - action: Deploy WAF rule to block directory traversal patterns targeting frm_graph
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-15990 vulnerability description
---

The Formidable Charts plugin for WordPress (versions 2.0.1 and below) contains a directory traversal vulnerability. An unauthenticated attacker can exploit this flaw by manipulating the 'frm_graph' parameter in HTTP requests. Successful exploitation allows for the reading of arbitrary files from the server filesystem, which may lead to the disclosure of sensitive configuration files, credentials, or application data.

The vulnerability is conditional: it requires Formidable Forms Lite, Formidable Forms Pro, and Formidable Charts to be active on the target site. Furthermore, the directory 'wp-content/uploads/frm-charts/' must exist, which typically occurs after the application renders an image-format chart. This vulnerability poses a significant risk to the confidentiality of the web server, particularly in environments hosting sensitive data or configuration files in the web root or accessible directories.

## Impact

Successful exploitation results in unauthorized access to arbitrary files on the host server. Depending on the target environment, this could lead to the exfiltration of sensitive information, such as wp-config.php files containing database credentials, API keys, or other environmental configuration data. This could facilitate further exploitation, privilege escalation, or full site takeover.

## Recommendation

* Update the Formidable Charts plugin to the latest version immediately to remediate CVE-2026-15990.
* Monitor web access logs for suspicious patterns in the 'frm_graph' parameter, specifically looking for sequences indicative of path traversal (e.g., '../', '..%2f').
* Restrict web server permissions to ensure that the WordPress application user has only the minimum necessary read access to the filesystem.
* Deploy a web application firewall (WAF) rule to inspect and block requests containing traversal sequences targeting the WordPress uploads directory.
