---
title: CVE-2026-58143 - Cotonti Siena 0.9.26 and earlier contains a cross-site request forgery vulnerability that allows una...
slug: 2026-07-cotonti-siena-csrf-rce
description: A Cross-Site Request Forgery (CSRF) vulnerability in Cotonti Siena versions 0.9.26 and earlier allows unauthenticated attackers to modify administrator configuration by tricking a logged-in administrator into submitting a forged POST request, enabling the upload and execution of arbitrary PHP files leading to remote code execution.
date: "2026-07-09T22:22:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cross-site-request-forgery
  - vulnerability
  - webserver
  - rce
  - php
vendors:
  - Cotonti
products:
  - Cotonti Siena <= 0.9.26
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Cotonti Siena 0.9.26 and earlier contains a cross-site request forgery vulnerability that allows unauthenticated attackers to modify administrator configuration
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: tricking a logged-in administrator into submitting a forged POST request
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: enabling any user with PFS access to upload and execute arbitrary PHP files on the server
    confidence_band: high
cves:
  - id: CVE-2026-58143
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-58143
rules:
  - title: Cotonti Siena CSRF PFS Whitelist Disable CVE-2026-58143
    description: Detects CVE-2026-58143 exploitation - HTTP POST requests to admin.php attempting to disable the PFS module's file extension whitelist (pfsfilecheck=0) via CSRF.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-58143 details a critical Cross-Site Request Forgery (CSRF) vulnerability affecting Cotonti Siena content management system versions 0.9.26 and earlier. This vulnerability allows an unauthenticated attacker to exploit a flaw in the `admin.php` configuration update handler, which neglects to invoke the application's CSRF validation function. By crafting a malicious web page or link, the attacker can trick a logged-in administrator into submitting a forged POST request. The primary impact of this action is the ability to disable the PFS module's file extension whitelist (`pfsfilecheck` parameter), setting it to `0`. This modification subsequently allows any user with PFS access to upload and execute arbitrary PHP files on the server, potentially leading to full remote code execution and compromise of the Cotonti Siena installation. The vulnerability was published on 2026-07-09, affecting a widely used open-source CMS.

## Attack Chain

1. **Craft Malicious Request**: An unauthenticated attacker crafts a malicious web page containing a forged POST request targeting the `admin.php` configuration update handler on the vulnerable Cotonti Siena instance. The request specifically includes the parameter `pfsfilecheck=0` to disable the PFS module's file extension whitelist.
2. **Social Engineering**: The attacker employs social engineering techniques (e.g., phishing, watering hole attack) to trick a legitimate, logged-in administrator of the Cotonti Siena instance into visiting the malicious web page or clicking a malicious link.
3. **Forged Request Execution**: The administrator's browser, being logged into Cotonti Siena, automatically executes the forged POST request to `admin.php` in the background when the malicious page is loaded.
4. **Configuration Modification**: The vulnerable Cotonti Siena application processes the incoming POST request to `admin.php` without performing adequate CSRF token validation, accepting the forged request as legitimate. The `pfsfilecheck` setting is updated to `0` in the application's configuration.
5. **Arbitrary File Upload Enabled**: With the `pfsfilecheck` whitelist disabled, the Cotonti Siena PFS module no longer restricts file uploads based on extension. This allows the attacker, or any user with PFS upload privileges, to upload files with dangerous extensions, such as `.php`.
6. **PHP File Upload**: The attacker uploads a malicious PHP web shell or other arbitrary PHP script to the server via the PFS module.
7. **Remote Code Execution**: The attacker accesses the uploaded PHP file via a web browser, causing the server to execute the arbitrary PHP code, achieving remote code execution (RCE) on the Cotonti Siena server.

## Impact

The successful exploitation of CVE-2026-58143 grants unauthenticated attackers a pathway to complete system compromise. By disabling file upload restrictions, attackers can upload and execute arbitrary PHP files, leading to remote code execution. This can result in full control over the compromised Cotonti Siena web server, allowing for data theft, defacement of the website, establishment of persistent backdoors, and further network penetration. While specific victim counts are not available, any organization utilizing Cotonti Siena versions 0.9.26 or earlier is at risk, particularly those that have not implemented additional web application firewall (WAF) protections or strong administrator awareness training against phishing.

## Recommendation

* **Patch CVE-2026-58143**: Immediately upgrade Cotonti Siena to a version greater than 0.9.26 that addresses CVE-2026-58143.
* **Implement CSRF Protection**: If immediate patching is not possible, implement custom CSRF protection mechanisms or use a Web Application Firewall (WAF) to block requests to `admin.php` that lack proper anti-CSRF tokens.
* **Monitor Web Server Logs**: Deploy the Sigma rule `Cotonti_Siena_CSRF_PFS_Whitelist_Disable_CVE_2026_58143` to your SIEM to detect HTTP POST requests targeting `/admin.php` that attempt to modify the `pfsfilecheck` parameter, indicating potential exploitation of CVE-2026-58143.
* **Educate Administrators**: Provide security awareness training to administrators on identifying and avoiding social engineering attacks, such as phishing, that could trick them into executing forged requests.
