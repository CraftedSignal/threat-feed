---
title: Arbitrary File Upload Vulnerability in Ultra Addons for Contact Form 7
slug: 2026-09-ultra-addons-rce
description: An arbitrary file upload vulnerability in the Ultra Addons for Contact Form 7 plugin, tracked as CVE-2026-82901, allows unauthenticated attackers to execute arbitrary code when the PDF Generator module is enabled.
date: "2026-09-26T21:01:01Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:ultraaddons:ultra_addons_for_contact_form_7:*:*:*:*:*:*:*:*
vendors:
  - Ultra Addons
products:
  - Ultra Addons for Contact Form 7 (<= 3.5.50)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The Ultra Addons for Contact Form 7 plugin for WordPress is vulnerable to Arbitrary File Upload due to insufficient file type validation.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.
    confidence_band: high
cves:
  - id: CVE-2026-82901
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82901
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Ultra Addons for Contact Form 7 to a version > 3.5.50
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-82901 advisory
  mitigation_plan:
    - priority: immediate
      action: Disable PDF Generator module in plugin settings
      owner: IT Operations
      addresses: CVE-2026-82901
      evidence: 'Note: This is only exploitable when the plugin''s PDF Generator module is enabled'
---

The Ultra Addons for Contact Form 7 plugin for WordPress is affected by a critical arbitrary file upload vulnerability, identified as CVE-2026-82901. The flaw resides within the 'uacf7_wpcf7_mail_components' function, which fails to adequately validate file types during upload operations. This vulnerability affects all versions of the plugin up to and including 3.5.50. 

The exploitation of this vulnerability is contingent upon the 'PDF Generator' module being enabled within the plugin settings, which is not the default configuration. When active, an unauthenticated attacker can upload malicious files, such as PHP shells, directly to the web server. Successful exploitation allows for remote code execution, granting the attacker control over the WordPress environment. Organizations using this plugin should verify if the PDF Generator module is active and update to a patched version immediately.

## Impact

Successful exploitation of CVE-2026-82901 enables unauthenticated remote code execution on WordPress instances. This can lead to full site compromise, data exfiltration, and the establishment of persistent backdoors. Because the plugin is a common add-on for Contact Form 7, a wide range of WordPress-based business sites are potentially at risk. The impact includes unauthorized access to site configuration, database content, and the ability to execute system-level commands with the privileges of the web server process.

## Recommendation

- Upgrade the Ultra Addons for Contact Form 7 plugin to a version beyond 3.5.50 immediately to remediate CVE-2026-82901.
- Review the configuration of the Ultra Addons plugin to ensure the PDF Generator module is disabled if it is not strictly required for business operations.
- Audit the WordPress uploads directory for unexpected files with executable extensions (e.g., .php, .php5, .phtml) created after the plugin was deployed.
- Monitor web server access logs for anomalous POST requests directed at plugin-specific endpoints associated with file uploads.
