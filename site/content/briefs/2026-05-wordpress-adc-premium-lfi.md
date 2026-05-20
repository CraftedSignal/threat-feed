---
title: Advanced Database Cleaner Premium WordPress Plugin Vulnerable to Local File Inclusion (CVE-2026-7522)
slug: 2026-05-wordpress-adc-premium-lfi
description: The Advanced Database Cleaner – Premium plugin for WordPress is vulnerable to Local File Inclusion (LFI) in versions up to 4.1.0, allowing authenticated attackers with subscriber-level access to include and execute arbitrary PHP files on the server via the 'template' parameter, potentially leading to access control bypass, sensitive data access, or code execution.
date: "2026-05-20T05:16:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - wordpress
  - lfi
  - cve-2026-7522
  - local-file-inclusion
vendors:
  - WordPress
products:
  - Advanced Database Cleaner – Premium plugin <= 4.1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Uncommonly Used File Attributes
cves:
  - id: CVE-2026-7522
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7522
rules:
  - title: Detect CVE-2026-7522 Exploitation - Advanced Database Cleaner Premium LFI
    description: Detects CVE-2026-7522 exploitation - Local File Inclusion in Advanced Database Cleaner Premium WordPress plugin via the 'template' parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Possible CVE-2026-7522 Exploitation - PHP Stream Wrapper Usage
    description: Detects possible CVE-2026-7522 exploitation - Usage of PHP stream wrappers like `php://filter` in 'template' parameter, indicating potential Local File Inclusion.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The Advanced Database Cleaner – Premium plugin for WordPress is susceptible to a Local File Inclusion (LFI) vulnerability, identified as CVE-2026-7522. This flaw affects versions up to and including 4.1.0. Authenticated attackers, possessing at least Subscriber-level privileges, can exploit this vulnerability by manipulating the 'template' parameter. This manipulation allows the inclusion and execution of arbitrary PHP files residing on the server. Successful exploitation can lead to bypassing access controls, obtaining sensitive data, or, if the attacker can upload PHP files, achieving arbitrary code execution on the target system. This vulnerability poses a significant risk to WordPress sites using the affected plugin versions.

## Attack Chain

1. An attacker gains Subscriber-level or higher access to the WordPress instance. This could be through compromised credentials or by registering a new user account.
2. The attacker crafts a malicious HTTP request targeting the vulnerable 'template' parameter within the Advanced Database Cleaner – Premium plugin.
3. The crafted request includes a path to a local PHP file that the attacker wants to include and execute. This could be an existing file on the server or a file previously uploaded by the attacker through another vulnerability or misconfiguration.
4. The WordPress application processes the request and includes the specified PHP file, effectively executing the code within that file.
5. If the included PHP file contains malicious code, it will be executed with the permissions of the web server user.
6. The attacker can leverage the executed code to perform various malicious actions, such as reading sensitive files, creating new administrative users, or injecting malicious code into other parts of the WordPress site.
7. The attacker might establish persistent access by creating a backdoor or modifying existing files to maintain control over the compromised system.

## Impact

Successful exploitation of this LFI vulnerability could allow attackers to bypass access controls and gain unauthorized access to sensitive information stored on the WordPress server, including database credentials, configuration files, and user data. Furthermore, in scenarios where attackers can upload PHP files, they can achieve arbitrary code execution, potentially leading to complete system compromise. The impact ranges from data theft and defacement to full control of the web server, affecting all sites hosted on the server.

## Recommendation

*   Apply the patch or upgrade to a version of the Advanced Database Cleaner – Premium plugin that is not vulnerable to CVE-2026-7522.
*   Deploy the Sigma rule `Detect CVE-2026-7522 Exploitation - Advanced Database Cleaner Premium LFI` to identify exploitation attempts targeting the vulnerable 'template' parameter.
*   Monitor web server logs for suspicious requests containing the 'template' parameter with unusual file paths, which may indicate LFI attempts.
*   Restrict file upload permissions to prevent unauthorized users from uploading malicious PHP files.
*   Implement strong password policies and multi-factor authentication to protect WordPress user accounts.
