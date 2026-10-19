---
title: Grav Allowlist Bypass Vulnerability
slug: 2026-10-grav-bypass
description: Grav versions 2.0.15 through 2.2.1 contain an allowlist bypass vulnerability allowing authenticated page editors to execute arbitrary public static methods, leading to unauthorized file system operations.
date: "2026-10-19T22:23:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:getgrav:grav:*:*:*:*:*:*:*:*
tags:
  - webserver
  - cms
  - bypass
vendors:
  - Grav
products:
  - Grav (2.0.15-2.2.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: Authenticated attacker with page-edit permissions can manipulate form fields to invoke unauthorized public static methods.
    confidence_band: high
cves:
  - id: CVE-2026-112780
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112780
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Grav to version 2.2.2 or later.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-112780
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Grav 2.2.2
      owner: IT Operations
      addresses: CVE-2026-112780
      evidence: Patch required for CVE-2026-112780
---

Grav versions 2.0.15 through 2.2.1 contain an allowlist bypass vulnerability (CVE-2026-112780) within the Flex form processing logic. This vulnerability allows an authenticated user with page-edit permissions to manipulate form fields by leveraging the 'replace-name@' syntax. By smuggling 'data-*@' directives past the application's internal callable check, an attacker can invoke unauthorized public static methods. Exploitation of this vulnerability grants the attacker the ability to perform sensitive file system operations, including the deletion of directories via 'Folder::delete', the movement of files via 'Folder::move', or unauthorized file reads through 'Utils::download'. This vulnerability poses a significant risk to the integrity and confidentiality of the CMS installation.

## Impact

Successful exploitation allows a low-privileged user with page-edit access to perform file system operations with the permissions of the web server process. This can result in site-wide disruption via directory deletion, unauthorized information disclosure through arbitrary file reads, and potential remote code execution pathways if configuration files are overwritten.

## Recommendation

- Upgrade Grav to version 2.2.2 or later immediately to address the underlying allowlist bypass logic.
- Review access control lists for the page-edit capability in Grav to ensure that only trusted users possess the ability to modify page content.
- Audit web server logs for HTTP POST requests directed at form processing endpoints containing the 'replace-name@' or 'data-*@' strings as form parameters.
