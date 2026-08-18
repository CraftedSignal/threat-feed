---
title: Arbitrary File Upload in Forminator Forms Plugin for WordPress
slug: 2026-08-forminator-rce
description: The Forminator Forms WordPress plugin version 1.56.1 and earlier contains an arbitrary file upload vulnerability allowing unauthenticated remote code execution via insufficient MIME type validation.
date: "2026-08-18T06:54:31Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - WPMU DEV
products:
  - Forminator Forms
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for unauthenticated attackers to upload files that may be executable, which makes remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-15748
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15748
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Forminator Forms plugin to 1.56.2 or higher
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-15748
  hunt_leads:
    - lead: Search for unknown .php, .phtml, or .phar files in wp-content/uploads
      technique_id: T1190
      data_needed:
        - File system auditing
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Arbitrary file upload leads to RCE
---

The Forminator Forms plugin for WordPress is vulnerable to an arbitrary file upload flaw (CVE-2026-15748) affecting all versions up to and including 1.56.1. The vulnerability resides in the handle_file_upload function, which utilizes a flawed blocklist for file extension validation. Attackers can bypass these security checks by employing pipe-alternative MIME type keys. Because the public submission handler trusts attacker-supplied configuration, a user can forge a Select field value to manipulate upload parameters. This allows unauthenticated attackers to bypass intended restrictions and upload malicious, potentially executable files to the web server, leading to full remote code execution (RCE). Given the nature of the vulnerability and the popularity of the plugin, immediate patching to version 1.56.2 or higher is required.

## Impact

Successful exploitation of CVE-2026-15748 grants unauthenticated remote code execution on the underlying web server. This provides an attacker with complete control over the WordPress instance, enabling data theft, site defacement, or persistence within the environment.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

* Update the Forminator Forms plugin to version 1.56.2 or later immediately to patch CVE-2026-15748.
* Audit web server access logs for anomalous POST requests to plugin-specific form submission endpoints that include unexpected file extensions or suspicious MIME type configurations.
* Monitor for newly created files within the WordPress uploads directory, specifically focusing on .php, .phtml, or .phar files.
* Deploy web application firewall (WAF) rules to restrict file uploads through Forminator endpoints, specifically looking for attempts to manipulate hidden form fields or MIME type parameters in POST bodies.
