---
title: Remote SQL Injection Vulnerability in code-projects Online Job Portal (CVE-2026-15676)
slug: 2026-07-code-projects-online-job-portal-sql-injection
description: A high-severity SQL injection vulnerability, CVE-2026-15676, exists in code-projects Online Job Portal up to version 1.0, allowing remote unauthenticated attackers to manipulate the database via the /Admin/DeleteUser.php file with a publicly available exploit.
date: "2026-07-14T06:20:58Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sql-injection
  - web-vulnerability
  - cve
vendors:
  - code-projects
products:
  - Online Job Portal <= 1.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A security flaw has been discovered in code-projects Online Job Portal up to 1.0. ... Remote exploitation of the attack is possible.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Performing a manipulation results in sql injection.
    confidence_band: med
cves:
  - id: CVE-2026-15676
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15676
  - https://code-projects.org/
  - https://github.com/shihuizhang-dazhi/MY-CVE/issues/4
  - https://vuldb.com/cve/CVE-2026-15676
  - https://vuldb.com/submit/855976
  - https://vuldb.com/vuln/378166
  - https://vuldb.com/vuln/378166/cti
rules:
  - title: Detects CVE-2026-15676 Exploitation - SQL Injection in Online Job Portal
    description: Detects exploitation attempts for CVE-2026-15676, an SQL injection vulnerability in code-projects Online Job Portal's /Admin/DeleteUser.php endpoint, by looking for suspicious patterns in web server logs.
    platform: sigma
    severity: high
    tactics:
      - impact
      - initial_access
    techniques:
      - T1190
      - T1505.001
    data_sources:
      - webserver
rules_count: 1
---

A significant security flaw, tracked as CVE-2026-15676, has been identified in `code-projects Online Job Portal` software, affecting all versions up to and including 1.0. This vulnerability is an SQL injection stemming from improper input handling within an unspecified function of the `/Admin/DeleteUser.php` file. The flaw enables remote exploitation by unauthenticated attackers, allowing them to perform arbitrary database manipulation. A public exploit for this vulnerability has been released, increasing the urgency for immediate patching or mitigation. Successful exploitation can lead to data theft, modification, or deletion, posing a critical risk to the integrity and confidentiality of the application's data.

## Attack Chain

1. An unauthenticated attacker crafts a malicious HTTP request targeting the `code-projects Online Job Portal` web application.
2. The request is directed to the vulnerable endpoint `/Admin/DeleteUser.php`.
3. The attacker embeds an SQL injection payload within an unspecified parameter or input field handled by this endpoint.
4. The web application processes the request, failing to properly validate or sanitize the malicious input.
5. This failure leads to the execution of the injected SQL commands on the backend database.
6. Successful execution allows for unauthorized database manipulation, such as data exfiltration, modification, or deletion, leading to data compromise or unauthorized administrative actions.

## Impact

The successful exploitation of CVE-2026-15676 can lead to severe consequences for organizations utilizing the affected `code-projects Online Job Portal`. Attackers can gain unauthorized access to the application's database, leading to the compromise of sensitive user information, administrative credentials, or job posting data. This could result in significant data breaches, reputational damage, and regulatory penalties. The ability to manipulate database entries could also allow attackers to deface the portal, inject malicious content, or disrupt its functionality entirely. Since the exploit is publicly available, a wide range of attackers could leverage this vulnerability, potentially affecting numerous organizations without proper defenses.

## Recommendation

* Immediately update `code-projects Online Job Portal` to a patched version once available. If a patch is not available, remove the `/Admin/DeleteUser.php` file or implement strict input validation and web application firewall (WAF) rules to filter malicious SQL injection attempts.
* Deploy the provided Sigma rule to detect attempts at exploiting CVE-2026-15676. Ensure your web server logs capture full URI and query string details for effective detection.
* Block access to the vulnerable endpoint ` /Admin/DeleteUser.php` from external networks if administrative functions are not required for public access, or enforce strong authentication mechanisms for this path.
* Review web server access logs for any suspicious requests targeting ` /Admin/DeleteUser.php` that match patterns described in the Sigma rule.
