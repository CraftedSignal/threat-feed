---
title: WordPress Contact Form Maker Plugin SQL Injection Vulnerability (CVE-2018-25347)
slug: 2026-05-wordpress-contact-form-sqli
description: WordPress Contact Form Maker Plugin version 1.12.20 is vulnerable to SQL injection, enabling authenticated attackers to manipulate database queries via AJAX actions (FormMakerSQLMapping and generete_csv_fmc) by injecting malicious SQL code through the 'name' and 'search_labels' parameters, potentially extracting sensitive database information or escalating privileges.
date: "2026-05-26T13:39:34Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sqli
  - wordpress
  - plugin
vendors:
  - WordPress
products:
  - Contact Form Maker Plugin 1.12.20
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2018-25347
    cvss: 7.1
    epss: 0.00024
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25347
rules:
  - title: Detects CVE-2018-25347 Exploitation — WordPress Contact Form Maker SQL Injection Attempt
    description: Detects CVE-2018-25347 exploitation — SQL injection attempts in WordPress Contact Form Maker Plugin via FormMakerSQLMapping AJAX action
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2018-25347 Exploitation — WordPress Contact Form Maker SQL Injection Attempt generete_csv_fmc
    description: Detects CVE-2018-25347 exploitation — SQL injection attempts in WordPress Contact Form Maker Plugin via generete_csv_fmc AJAX action
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

The WordPress Contact Form Maker Plugin version 1.12.20 is susceptible to SQL injection vulnerabilities. Authenticated attackers can exploit these vulnerabilities to manipulate database queries through specific AJAX actions, namely 'FormMakerSQLMapping' and 'generete_csv_fmc'. By injecting malicious SQL code via the 'name' and 'search_labels' parameters, attackers can potentially extract sensitive information stored in the database or elevate their privileges within the WordPress application. This vulnerability allows malicious actors to compromise the integrity and confidentiality of data managed by the Contact Form Maker plugin. Defenders should prioritize patching and detection efforts to mitigate potential exploitation.

## Attack Chain

1.  Attacker authenticates to the WordPress application.
2.  Attacker crafts a malicious HTTP request targeting the 'FormMakerSQLMapping' or 'generete_csv_fmc' AJAX action.
3.  The crafted request includes SQL injection payloads within the 'name' or 'search_labels' parameters.
4.  The WordPress server processes the request, passing the malicious SQL code to the database query.
5.  The injected SQL code modifies the intended database query, allowing the attacker to extract sensitive data.
6.  The attacker retrieves the extracted data from the server response.
7.  The attacker uses the extracted data to escalate privileges or gain further access to the WordPress application.

## Impact

Successful exploitation of this vulnerability can lead to the compromise of sensitive data stored within the WordPress database. This may include user credentials, customer data, or other confidential information managed by the Contact Form Maker plugin. Attackers can potentially use this access to escalate privileges, gain control of the WordPress site, and potentially use it as a beachhead for further attacks. The affected plugin version is 1.12.20, indicating that sites which have not applied updates are vulnerable.

## Recommendation

*   Upgrade the WordPress Contact Form Maker Plugin to a version later than 1.12.20 to remediate the vulnerability (CVE-2018-25347).
*   Deploy the Sigma rule provided below to detect potential SQL injection attempts targeting the vulnerable AJAX actions.
*   Monitor web server logs for suspicious POST requests to 'FormMakerSQLMapping' or 'generete_csv_fmc' containing SQL syntax in the 'name' or 'search_labels' parameters.
