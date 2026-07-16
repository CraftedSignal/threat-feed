---
title: Uncanny Automator WordPress Plugin Vulnerable to Arbitrary File Deletion (CVE-2026-15008)
slug: 2026-07-uncanny-automator-file-deletion
description: A critical arbitrary file deletion vulnerability, CVE-2026-15008, exists in The Uncanny Automator plugin for WordPress, versions up to and including 7.3.1.4, due to insufficient file path validation in the `fr_token` function, allowing unauthenticated attackers to delete arbitrary files on the server and potentially achieve remote code execution (RCE) by targeting critical files like `wp-config.php`, provided a Forminator form is linked to an 'Everyone' configured Uncanny Automator recipe, enabling the submission of a malicious serialized payload that leverages a gadget chain within the plugin's `Action_Helpers_Email __destruct()` method.
date: "2026-07-16T09:19:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - vulnerability
  - arbitrary-file-deletion
  - deserialization
vendors:
  - The Uncanny Automator
products:
  - Uncanny Automator – Easy Automation, Integration, Webhooks & Workflow Builder Plugin (<= 7.3.1.4)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: can easily lead to remote code execution when the right file is deleted (such as wp-config.php)
    confidence_band: med
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: arbitrary file deletion due to insufficient file path validation in the fr_token function
    confidence_band: high
cves:
  - id: CVE-2026-15008
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15008
---

A significant arbitrary file deletion vulnerability, identified as CVE-2026-15008, affects The Uncanny Automator plugin for WordPress, specifically in all versions up to and including 7.3.1.4. This flaw stems from insufficient file path validation within the `fr_token` function, enabling unauthenticated attackers to delete arbitrary files on the vulnerable server. The exploitation pathway for this vulnerability requires a WordPress site running the affected Uncanny Automator plugin that also has a Forminator form connected to an Uncanny Automator recipe configured for 'Everyone'. This specific configuration allows for unauthenticated form submissions, which attackers can then leverage to supply a malicious serialized payload. The plugin itself contains a gadget chain via the `Action_Helpers_Email __destruct()` method, eliminating the need for external gadget libraries and simplifying exploitation. Successful exploitation can lead to severe consequences, including remote code execution, particularly if crucial system files like `wp-config.php` are targeted and deleted.

## Attack Chain

1. **Reconnaissance and Configuration Identification**: An unauthenticated attacker identifies a WordPress site running The Uncanny Automator plugin (version 7.3.1.4 or earlier) and determines if a Forminator form is integrated with an Uncanny Automator recipe configured for 'Everyone' (allowing public submissions).
2. **Malicious Payload Crafting**: The attacker crafts a PHP serialized payload designed to trigger the arbitrary file deletion vulnerability by leveraging the gadget chain available in the plugin's `Action_Helpers_Email __destruct()` method and targeting the `fr_token` function.
3. **Payload Delivery**: The attacker submits the crafted malicious serialized payload via an unauthenticated POST request to the publicly accessible Forminator form endpoint.
4. **Application Processing**: The WordPress application, specifically the Uncanny Automator plugin, receives and processes the Forminator submission, which includes the malicious serialized payload.
5. **Deserialization and Gadget Chain Execution**: During the processing, the application deserializes the payload, triggering the `Action_Helpers_Email __destruct()` method, which in turn exploits the insufficient file path validation in the `fr_token` function.
6. **Arbitrary File Deletion**: The vulnerability allows the attacker to delete an arbitrary file on the server. For instance, the attacker could specify `wp-config.php` for deletion.
7. **Impact (WordPress Reinstallation)**: If `wp-config.php` is deleted, accessing the WordPress site again will trigger the WordPress installation wizard, as the configuration file is missing.
8. **Potential Remote Code Execution**: By exploiting the reinstallation process or other means after deleting critical files, the attacker can potentially achieve remote code execution on the server.

## Impact

The arbitrary file deletion vulnerability (CVE-2026-15008) in The Uncanny Automator plugin poses a critical risk to affected WordPress installations. Unauthenticated attackers can leverage this flaw to delete any file on the server, leading to severe system compromise. The most significant consequence is the deletion of critical files like `wp-config.php`, which can lead to a full WordPress reinstallation. This reinstallation process could then be abused by an attacker to inject malicious code or configurations, effectively leading to remote code execution and full control over the compromised server. The lack of authentication required for exploitation broadens the attack surface significantly, making any WordPress site with the vulnerable plugin and the specified configuration a potential target.

## Recommendation

* Patch CVE-2026-15008 immediately by updating The Uncanny Automator - Easy Automation, Integration, Webhooks & Workflow Builder Plugin to a version greater than 7.3.1.4.
* Review your Uncanny Automator recipes connected to Forminator forms to ensure that sensitive operations are not configured for 'Everyone' access without proper authentication.
* Monitor web server access logs for unusual POST requests to Forminator submission endpoints, especially those containing serialized payload patterns or resulting in unexpected application behavior (e.g., redirection to `/wp-admin/setup-config.php`).
* Deploy file integrity monitoring (FIM) solutions to detect unauthorized modifications or deletions of critical WordPress files, such as `wp-config.php` and core installation files.
