---
title: Local File Inclusion in WPCafe WordPress Plugin (CVE-2026-75028)
slug: 2026-10-wpcafe-lfi
description: The WPCafe WordPress plugin contains a local file inclusion vulnerability in its template scope function, allowing authenticated contributors to execute arbitrary PHP files.
date: "2026-10-03T08:54:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wpcafe:restaurant_menu_online_food_ordering_table_booking_system:*:*:*:*:*:*:*:*
tags:
  - wordpress
  - lfi
  - cve-2026-75028
vendors:
  - WPCafe
products:
  - WPCafe – Restaurant Menu, Online Food Ordering & Table Booking System (<= 3.0.18)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The WPCafe plugin is vulnerable to Local File Inclusion via the template scope function.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: This makes it possible for authenticated attackers... to include and execute arbitrary .php files on the server.
    confidence_band: high
cves:
  - id: CVE-2026-75028
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-75028
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch WPCafe plugin to version 3.0.19 or later
      owner: IT Operations
      due: 24h
      evidence: Source confirms versions up to 3.0.18 are vulnerable.
  hunt_leads:
    - lead: Search for POST/GET requests targeting WPCafe plugin endpoints with suspicious file paths in parameters
      technique_id: T1210
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability is triggered via the template scope function.
  mitigation_plan:
    - priority: immediate
      action: Upgrade WPCafe plugin
      owner: IT Operations
      addresses: CVE-2026-75028
      evidence: NVD vulnerability notice
---

The WPCafe - Restaurant Menu, Online Food Ordering & Table Booking System plugin for WordPress is vulnerable to local file inclusion (LFI) in all versions up to and including 3.0.18. The vulnerability resides within the template scope function of the plugin. An attacker with authenticated contributor-level access or higher can leverage this flaw to include and execute arbitrary .php files located on the server. If an attacker manages to upload a malicious PHP file to the server through other vectors, this vulnerability provides a mechanism to execute that code, potentially leading to a full system compromise. This issue affects any WordPress environment running the vulnerable plugin version and requires immediate patching to the latest available release.

## Attack Chain

1. Attacker obtains authenticated access to a WordPress site as a user with contributor privileges or higher.
2. Attacker uploads a malicious PHP file to a directory on the server, often leveraging separate file upload vectors if available.
3. Attacker identifies the path to the uploaded malicious file.
4. Attacker crafts a request targeting the WPCafe plugin template scope function, injecting the path of the malicious PHP file.
5. The plugin fails to properly validate the template parameter, leading to the inclusion of the attacker-specified file.
6. The server interprets and executes the arbitrary PHP code contained within the included file.
7. Attacker gains code execution on the underlying server to achieve persistence or data exfiltration.

## Impact

Successful exploitation allows authenticated attackers to execute arbitrary PHP code on the server, potentially leading to unauthorized data access, privilege escalation, and full site compromise. This vulnerability poses a significant risk to restaurant and service-based businesses relying on the WPCafe plugin for online ordering and booking operations.

## Recommendation

* Patch the WPCafe plugin to the latest version immediately to remediate CVE-2026-75028.
* Conduct a site-wide audit for unauthorized PHP files in common upload directories, such as /wp-content/uploads/.
* Review access control logs for unusual activity from contributor-level accounts, particularly those interacting with plugin-specific parameters.
* Utilize WordPress security auditing tools to scan for known vulnerabilities and ensure plugin configurations follow the principle of least privilege.
