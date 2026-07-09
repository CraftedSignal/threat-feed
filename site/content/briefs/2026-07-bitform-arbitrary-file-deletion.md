---
title: CVE-2026-14372 - The Bit Form WordPress Plugin Arbitrary File Deletion
slug: 2026-07-bitform-arbitrary-file-deletion
description: The Bit Form WordPress plugin (versions up to 3.1.1) is vulnerable to arbitrary file deletion due to insufficient file path validation, allowing authenticated attackers with subscriber-level access to delete critical server files like wp-config.php, potentially leading to remote code execution.
date: "2026-07-09T11:19:20Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - plugin
  - vulnerability
  - web
  - rce
  - file-deletion
vendors:
  - Bit Form
products:
  - The Bit Form – Contact Form, Payment Forms, Multi Step Forms, Calculator & Custom Form Builder plugin for WordPress (<= 3.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: authenticated attackers, with subscriber-level access and above
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: can easily lead to remote code execution when the right file is deleted (such as wp-config)
    confidence_band: med
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: vulnerable to arbitrary file deletion due to insufficient file path validation in the deleteFiles function
    confidence_band: high
cves:
  - id: CVE-2026-14372
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14372
---

A critical vulnerability, tracked as CVE-2026-14372, has been identified in The Bit Form - Contact Form, Payment Forms, Multi Step Forms, Calculator & Custom Form Builder plugin for WordPress, affecting all versions up to and including 3.1.1. This flaw stems from insufficient file path validation within the plugin's `deleteFiles` function, enabling authenticated attackers with at least subscriber-level privileges to perform arbitrary file deletion on the host server. The potential impact of this vulnerability is severe, as the deletion of sensitive files, such as `wp-config.php`, can easily pave the way for remote code execution (RCE) by disrupting the WordPress installation's integrity and allowing for potential re-installation hijacking or exploitation of other vulnerabilities in the compromised state. Organizations using this plugin should prioritize patching to mitigate the risk of server compromise.

## Attack Chain

1. **Initial Access**: An attacker obtains valid credentials for a WordPress user account with subscriber-level access or higher on a website running the vulnerable Bit Form plugin.
2. **Exploitation Request**: The attacker crafts and sends a malicious HTTP POST request to a specific endpoint within the WordPress installation, targeting the vulnerable `deleteFiles` function of The Bit Form plugin.
3. **Path Traversal Insertion**: The crafted request includes path traversal sequences (e.g., `../`, `..\`) embedded within the parameter designated for specifying the file path to be deleted.
4. **Arbitrary File Deletion**: Due to inadequate file path validation by the `deleteFiles` function, the plugin processes the malformed request and proceeds to delete an arbitrary file located outside its intended directory, such as `wp-config.php`.
5. **WordPress Instability**: The deletion of a critical file like `wp-config.php` renders the WordPress installation inoperable or reverts it to an unconfigured state, often triggering the initial setup/re-installation process.
6. **Remote Code Execution**: The attacker leverages the now unconfigured WordPress state, either by completing a malicious re-installation or exploiting other vulnerabilities that become feasible due to the missing configuration file, to achieve Remote Code Execution on the underlying server.

## Impact

The successful exploitation of CVE-2026-14372 can lead to severe consequences for affected WordPress websites. Authenticated attackers can delete critical system files, including but not limited to `wp-config.php`, which stores database credentials and other vital configuration settings. This can immediately lead to denial of service, data corruption, and potentially full website defacement or compromise. If `wp-config.php` is deleted, attackers can often trigger a re-installation of WordPress and gain administrative control, ultimately leading to remote code execution on the server and complete takeover of the website and hosting environment.

## Recommendation

* Patch CVE-2026-14372 by updating The Bit Form plugin to a patched version immediately.
* Review web server access logs for any suspicious POST requests to `/wp-admin/admin-ajax.php` or other plugin endpoints containing `../` or `..\` sequences, especially in conjunction with parameters related to file deletion functions.
