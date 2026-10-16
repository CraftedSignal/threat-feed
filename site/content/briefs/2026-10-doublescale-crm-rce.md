---
title: Arbitrary File Upload in DoubleScale CRM Plugin for WordPress
slug: 2026-10-doublescale-crm-rce
description: An arbitrary file upload vulnerability in the DoubleScale CRM plugin for WordPress up to version 1.5.1 allows authenticated subscribers to achieve remote code execution when the Helpdesk module is enabled.
date: "2026-10-16T10:25:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:doublescale:all-in-one_crm:*:*:*:*:*:wordpress:*:*
tags:
  - wordpress
  - plugin
  - rce
  - file-upload
  - cve-2026-111311
vendors:
  - DoubleScale
products:
  - DoubleScale | All-in-One CRM – Sales, Multi-Channel Marketing, Newsletter, Booking, Helpdesk, Automation, MCP & More
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The DoubleScale plugin for WordPress is vulnerable to Arbitrary File Upload... making remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Successful exploitation allows an authenticated attacker... to execute arbitrary code on the underlying server.
    confidence_band: high
cves:
  - id: CVE-2026-111311
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111311
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update DoubleScale CRM plugin to the latest patched version
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-111311 vulnerability in version 1.5.1
  mitigation_plan:
    - priority: immediate
      action: Disable the Helpdesk module in DoubleScale CRM
      owner: IT Operations
      addresses: CVE-2026-111311
      evidence: Exploitation requires the Helpdesk module to be enabled
---

The DoubleScale CRM plugin for WordPress, in versions up to and including 1.5.1, contains a critical arbitrary file upload vulnerability. The flaw exists within the store_upload function, which is exposed via a REST API endpoint registered only when the Helpdesk module is active. The root cause is a flawed extension validation mechanism in the extension_is_allowed function. This function incorrectly validates files by relying on wp_check_filetype, which can return an empty type for unrecognized extensions such as .php, and subsequently failing open. Because the vulnerability only requires a low-privilege (subscriber) account and lacks sufficient capability checks, an attacker can upload arbitrary executable files to the web server, resulting in remote code execution (RCE). This vulnerability is tracked as CVE-2026-111311.

## Impact

Successful exploitation of CVE-2026-111311 allows an authenticated attacker with at least subscriber-level permissions to execute arbitrary code on the underlying server. This could lead to a complete site compromise, data exfiltration, or lateral movement within the hosting environment. WordPress installations using the DoubleScale plugin with the Helpdesk module enabled are at high risk.

## Recommendation

* Immediately update the DoubleScale CRM plugin to a version addressing CVE-2026-111311.
* Disable the Helpdesk module if it is not required for business operations to mitigate the attack surface for this vulnerability.
* Audit user roles and permissions to ensure that subscriber accounts are limited to necessary functions only.
* Monitor web server logs for POST requests to REST endpoints associated with the DoubleScale CRM plugin, particularly those resulting in file creation within the WordPress uploads directory.
