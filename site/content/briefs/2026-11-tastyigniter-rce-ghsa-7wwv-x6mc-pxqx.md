---
brief_id: brief-2026-11-25-tastyigniter-rce-ghsa-7wwv-x6mc-pxqx
event_id: brief-2026-11-25-tastyigniter-rce-ghsa-7wwv-x6mc-pxqx
revision: 1
activity_at: "2026-11-25T23:12:16Z"
title: TastyIgniter Media Manager remote code execution (CVE-2026-69179)
slug: 2026-11-tastyigniter-rce-ghsa-7wwv-x6mc-pxqx
description: TastyIgniter versions prior to 4.3.1 are vulnerable to an unrestricted file upload flaw in the Media Manager, allowing an authenticated administrator to achieve remote code execution by reconfiguring server file handling via .htaccess.
date: "2026-11-25T23:12:16Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
vendors:
  - TastyIgniter
products:
  - TastyIgniter
product_versions:
  - product: TastyIgniter
    range: < 4.3.1
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated administrator can upload a .htaccess file that reconfigures the server to interpret arbitrary file extensions as PHP.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: Web Shell
    evidence: By subsequently uploading a PHP script disguised as an image file, the attacker can achieve remote code execution on the underlying server.
    confidence_band: high
cves:
  - id: CVE-2026-69179
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-7wwv-x6mc-pxqx
rules:
  - title: Detect CVE-2026-69179 exploitation - suspicious file upload to media manager
    description: Detects the upload of .htaccess files via the TastyIgniter Media Manager, which is a required step for this RCE exploit.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  mitigation_plan:
    - priority: immediate
      action: Upgrade TastyIgniter to version 4.3.1 or later
      evidence: Composer package composer/tastyigniter/tastyigniter < 4.3.1 is vulnerable.
---

## Overview
TastyIgniter versions before 4.3.1 contain an unrestricted file upload vulnerability in the Media Manager component. The application fails to validate uploaded files, allowing an authenticated administrator to upload a .htaccess file. This file can be used to reconfigure the web server to interpret arbitrary file types (e.g., .jpg) as PHP code. Following this, the attacker can upload a secondary file disguised as an image containing malicious PHP payloads to execute commands on the underlying server.

## Attack Chain
1. Attacker authenticates to the TastyIgniter administration panel.
2. Attacker navigates to the Media Manager component.
3. Attacker uploads a custom .htaccess file designed to map a specific image extension to the PHP handler.
4. Attacker uploads a malicious file containing PHP code saved with the mapped image extension (e.g., .jpg).
5. Attacker makes an HTTP request to the uploaded file location to trigger execution of the PHP payload.

## Impact
An authenticated administrator can achieve full remote code execution on the underlying server, potentially leading to total system compromise, data theft, or lateral movement within the network.

## Recommendation
Upgrade the TastyIgniter installation to version 4.3.1 or later. If an immediate upgrade is not possible, restrict administrative access to the Media Manager and implement server-side restrictions to prevent the upload or execution of .htaccess files in web-accessible directories.
