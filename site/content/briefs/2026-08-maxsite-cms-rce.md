---
title: Unauthenticated Remote Code Execution in MaxSite CMS via Config Injection
slug: 2026-08-maxsite-cms-rce
description: MaxSite CMS is vulnerable to remote code execution due to improper input sanitization of the db_dbprefix parameter, allowing unauthenticated attackers to inject persistent PHP code into the database configuration file.
date: "2026-08-04T22:02:07Z"
lastmod: "2026-08-05T02:03:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - web-application
  - cms
  - vulnerability
vendors:
  - MaxSite
products:
  - MaxSite CMS
  - MaxSite CMS (109.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: MaxSite CMS contains a remote code execution vulnerability that allows unauthenticated attackers to inject arbitrary PHP code.
    confidence_band: high
cves:
  - id: CVE-2026-70553
    cvss: 9.8
  - id: CVE-2026-70554
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70553
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70554
  - https://nvd.nist.gov/vuln/detail/CVE-2026-70552
rules:
  - title: Detects CVE-2026-70553 Exploitation - POST Request with Malicious db_dbprefix
    description: Detects exploitation of CVE-2026-70553 by identifying POST requests to the install endpoint containing a single quote in the db_dbprefix parameter, which is characteristic of the injection vector.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy the Sigma rule to detect POST requests to the install endpoint with anomalous characters.
      owner: Detection Engineering
      due: 24h
      evidence: Source document describes this as the primary exploitation vector.
  mitigation_plan:
    - priority: immediate
      action: Disable or block access to the CMS installation path in the web server configuration.
      owner: IT Operations
      addresses: CVE-2026-70553
      evidence: Vulnerability exists in the install endpoint.
updates:
  - at: "2026-08-04T22:02:12Z"
    level: L2
    summary: added CVE-2026-70554
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70554
  - at: "2026-08-05T02:03:54Z"
    level: L2
    summary: added coverage for MaxSite CMS (109.5)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-70552
---

MaxSite CMS contains a critical remote code execution vulnerability (CVE-2026-70553) affecting the application's installation process. An unauthenticated attacker can exploit this flaw by submitting crafted POST requests to the CMS installation endpoint, even after the initial installation is complete. By providing a specifically crafted 'db_dbprefix' parameter containing a single quote, an attacker can break out of the PHP string literal within 'application/config/database.php'. This allows for the injection and subsequent execution of arbitrary PHP code. The injected payload is written to the configuration file and is executed by the web server process during every subsequent application request, granting the attacker persistent code execution capabilities with the privileges of the web service account.

## Impact

Successful exploitation results in full server-side compromise, as the attacker achieves unauthenticated remote code execution. This allows for data exfiltration, lateral movement within the network, or complete takeover of the affected web application. This vulnerability poses a severe risk to any organization running an exposed MaxSite CMS instance.

## Recommendation

- Patch MaxSite CMS to the latest version provided by the vendor to address the improper input sanitization in the installation module.
- Review the 'application/config/database.php' file for any anomalous PHP code or unexpected modifications to the 'db_dbprefix' variable.
- Restrict access to the CMS installation endpoint (e.g., /install) via web application firewall or server configuration rules after the initial site setup is complete.
- Audit web server logs for suspicious POST requests targeting installation directories that occur outside of documented deployment windows.
