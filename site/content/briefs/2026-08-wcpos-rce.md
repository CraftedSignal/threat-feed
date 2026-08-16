---
title: Authenticated Remote Code Execution in WCPOS WordPress Plugin
slug: 2026-08-wcpos-rce
description: The WCPOS plugin for WooCommerce is vulnerable to authenticated remote code execution via a template engine misconfiguration that allows injection and execution of arbitrary PHP code.
date: "2026-08-16T06:25:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - rce
  - web-application
  - cve-2026-17581
vendors:
  - WordPress
products:
  - WCPOS – Point of Sale (POS) plugin for WooCommerce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: This requires the attacker to have Shop Manager-level access or above.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: resulting in remote code execution on the server.
    confidence_band: high
cves:
  - id: CVE-2026-17581
    cvss: 7.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17581
---

The WCPOS - Point of Sale (POS) plugin for WooCommerce (versions 1.9.14 and earlier) contains a critical remote code execution (RCE) vulnerability identified as CVE-2026-17581. The flaw exists within the 'thermal' template engine, where the Receipt_Renderer_Factory incorrectly dispatches thermal templates to the Legacy_Php_Renderer. This improper handling allows an authenticated user with 'Shop Manager' privileges or higher to inject arbitrary PHP code into a template post. When saved, this template is written to a temporary file and subsequently executed via a PHP include() statement. Because this requires Shop Manager privileges, the attack vector is likely to be utilized by compromised accounts or malicious insiders rather than unauthenticated external actors.

## Attack Chain

1. Attacker gains access to a WordPress account with 'Shop Manager' or administrator level privileges.
2. Attacker authenticates to the WordPress dashboard.
3. Attacker navigates to the WCPOS plugin template management interface.
4. Attacker submits a POST request containing malicious PHP code within the template editor under the 'thermal' template engine settings.
5. The plugin performs a nonce check (wcpos_template_settings) and permission check (manage_woocommerce_pos).
6. The Receipt_Renderer_Factory receives the request and misroutes the 'thermal' template to the Legacy_Php_Renderer.
7. The application writes the malicious payload to a temporary file on the web server's local file system.
8. The application calls include() on the generated temporary file, leading to server-side code execution.

## Impact

Successful exploitation results in full remote code execution on the WordPress host server, granting the attacker the ability to execute arbitrary commands, access database credentials, exfiltrate site data, or install persistent web shells. The impact is limited to environments where the attacker can obtain authenticated access to a Shop Manager account or higher.

## Recommendation

* Immediately update the WCPOS - Point of Sale (POS) plugin for WooCommerce to version 1.9.15 or later to patch the template rendering logic.
* Audit WordPress user roles to identify and restrict accounts with 'Shop Manager' capabilities.
* Monitor web server access logs for anomalous POST requests to WCPOS plugin endpoints from authenticated administrative sessions.
* Review site file integrity for unexpected PHP files created within the WordPress temporary directory paths.
