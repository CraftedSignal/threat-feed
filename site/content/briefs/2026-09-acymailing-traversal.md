---
title: Path Traversal Vulnerability in AcyMailing WordPress Plugin
slug: 2026-09-acymailing-traversal
description: The AcyMailing WordPress plugin is vulnerable to unauthenticated directory traversal, allowing attackers to read arbitrary files on the server when the Embed images feature is enabled.
date: "2026-09-11T01:10:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:acymailing:acymailing:*:*:*:*:*:wordpress:*:*
tags:
  - web-application
  - vulnerability
  - directory-traversal
vendors:
  - AcyMailing
products:
  - AcyMailing (<= 11.0.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: This makes it possible for unauthenticated attackers to read the contents of arbitrary files on the server
    confidence_band: high
cves:
  - id: CVE-2026-77807
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-77807
rules:
  - title: Detects CVE-2026-77807 Exploitation - Directory Traversal in AcyMailing
    description: Detects exploitation attempts against AcyMailing by identifying path traversal sequences in the user[name] parameter.
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
    - action: Disable Embed images feature in AcyMailing settings
      owner: IT Operations
      due: 24h
      evidence: Exploitation requires Embed images option in AcyMailing configuration being enabled.
  mitigation_plan:
    - priority: immediate
      action: Monitor web logs for exploitation patterns defined in the detection rule
      owner: SOC
      addresses: CVE-2026-77807
      evidence: Vulnerability allows unauthenticated attackers to read arbitrary files
---

The AcyMailing plugin for WordPress, a newsletter and marketing automation tool, contains a path traversal vulnerability in all versions up to and including 11.0.4. The flaw exists within the processing of the user[name] parameter. An unauthenticated remote attacker can leverage this vulnerability to perform directory traversal attacks, resulting in the unauthorized disclosure of arbitrary files stored on the underlying web server.

Successful exploitation is contingent upon the site administrator having the Embed images configuration option enabled within the AcyMailing settings. This vulnerability poses a significant risk to confidentiality, as it enables the retrieval of sensitive system files, configuration files, or database credentials. Defenders should monitor web server logs for requests containing path traversal sequences directed at the vulnerable component and ensure the plugin is updated to a patched version once available.

## Impact

Successful exploitation allows unauthenticated attackers to read sensitive files on the server hosting the WordPress instance. This could lead to the exposure of configuration data, local credentials, or environment variables, potentially facilitating further unauthorized access to the web application or the hosting infrastructure.

## Recommendation

- Upgrade the AcyMailing WordPress plugin to a version released after 11.0.4 as soon as a patch becomes available.
- Disable the Embed images feature in the AcyMailing configuration until the plugin can be updated.
- Implement web application firewall (WAF) rules to detect and block incoming HTTP requests containing directory traversal sequences like ../ directed at the plugin endpoints.
- Audit web server access logs for anomalous GET or POST requests that contain high frequencies of relative path navigation characters.
