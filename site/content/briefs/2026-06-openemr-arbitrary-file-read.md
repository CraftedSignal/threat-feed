---
title: OpenEMR Authenticated Arbitrary File Read (CVE-2026-24849)
slug: 2026-06-openemr-arbitrary-file-read
description: A public exploit (EDB-52610) has been published for OpenEMR versions prior to 7.0.4, detailing an authenticated arbitrary file read vulnerability (CVE-2026-24849) in the Fax/SMS module's `EtherFaxActions::disposeDoc()` method, which allows a low-privileged authenticated user to read and potentially delete any file accessible by the web server user due to a lack of path validation on the `file_path` request parameter.
date: "2026-06-14T09:49:54Z"
lastmod: "2026-10-19T18:22:41Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:open-emr:openemr:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-DOANY1-CVE-2026-24849&utm_source=rss&utm_medium=rss
tags:
  - webapps
  - arbitrary-file-read
  - openemr
  - cve
vendors:
  - OpenEMR
products:
  - OpenEMR < 7.0.4 (< 7.0.4)
affected_os:
  - Ubuntu 22.04
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
cves:
  - id: CVE-2026-24849
    cvss: 9.9
    epss: 0.02251
references:
  - https://www.exploit-db.com/exploits/52610
  - https://github.com/openemr/openemr/security/advisories/GHSA-w6vc-hx2x-48pc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-24849
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-DOANY1-CVE-2026-24849&utm_source=rss&utm_medium=rss
rules:
  - title: Detects CVE-2026-24849 Exploitation - OpenEMR Arbitrary File Read Attempt
    description: Detects exploitation attempts of CVE-2026-24849 (OpenEMR Authenticated Arbitrary File Read) by looking for requests to the vulnerable Fax/SMS module endpoint with a file_path parameter. This indicates an attacker attempting to read arbitrary files.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1005
      - T1190
    data_sources:
      - webserver
  - title: Detects CVE-2026-24849 Exploitation - OpenEMR Sensitive File Read
    description: Detects highly suspicious exploitation of CVE-2026-24849 (OpenEMR Arbitrary File Read) targeting known sensitive system or application configuration files. This indicates a high likelihood of compromise and sensitive data exposure.
    platform: sigma
    severity: critical
    tactics:
      - collection
      - exfiltration
    techniques:
      - T1005
    data_sources:
      - webserver
rules_count: 2
updates:
  - at: "2026-10-19T18:22:41Z"
    level: L2
    summary: poc_available; openemr < 7.0.4 version < 7.0.4
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-DOANY1-CVE-2026-24849&utm_source=rss&utm_medium=rss
---

A public exploit (EDB-52610) has been released for OpenEMR versions prior to 7.0.4, specifically tested on OpenEMR 7.0.2. This vulnerability, identified as CVE-2026-24849, is an authenticated arbitrary file read flaw located in the Fax/SMS module (`oe-module-faxsms`). The `EtherFaxActions::disposeDoc()` (or `disposeDocument()`) method, which is accessible via `index.php` within the module, fails to validate the `file_path` request parameter before passing it to `readfile()`. This allows any authenticated user with low privileges (e.g., receptionist, clinician) to read arbitrary files from the underlying server's filesystem, including sensitive configuration files like database credentials (`sqlconf.php`) or system files (`/etc/passwd`). Furthermore, the `disposeDoc()` method calls `unlink()` on the target file after reading, introducing a destructive element where files can be deleted if the web server user has write permissions. The availability of this public exploit significantly increases the risk for unpatched OpenEMR instances.

## Attack Chain

1.  **Initial Access**: An attacker obtains valid login credentials for any low-privileged OpenEMR user account.
2.  **Authentication**: The attacker authenticates to the OpenEMR system, establishing a valid session.
3.  **Vulnerability Exploitation**: The attacker sends a specially crafted GET request to the vulnerable endpoint: `/interface/modules/custom_modules/oe-module-faxsms/index.php`.
4.  **Parameter Injection**: The GET request includes parameters such as `type=fax`, `_ACTION_COMMAND` (either `disposeDoc` or `disposeDocument`), `action=download`, and a malicious `file_path` parameter pointing to a target file on the server's filesystem (e.g., `/etc/passwd`, `/var/www/html/openemr/sites/default/sqlconf.php`).
5.  **Arbitrary File Read**: The `disposeDoc()` method, lacking proper path validation, reads the content of the specified arbitrary file and returns it within the HTTP response body to the attacker.
6.  **Sensitive Data Exposure**: The attacker successfully retrieves sensitive information such as database credentials, API keys, or system configuration details.
7.  **File Deletion (Optional Impact)**: If the web server process has write permissions to the targeted file, the `disposeDoc()` method proceeds to call `unlink()` on the file, permanently deleting it from the server.
8.  **Post-Exploitation**: The attacker uses the exfiltrated sensitive data for further privilege escalation, lateral movement, or to gain control over the database.

## Impact

The successful exploitation of CVE-2026-24849 can lead to severe consequences, including the unauthorized disclosure of highly sensitive data. Attackers can read critical system files like `/etc/passwd` to enumerate users or `sites/default/sqlconf.php` to obtain database credentials, compromising patient records or administrative data. The ability to delete files via `unlink()` poses a risk of data destruction and denial of service if critical application files are targeted and removed. Although the exploit requires authentication, the low privilege level needed means many user accounts could be leveraged. Given OpenEMR's common use in healthcare, a breach could lead to HIPAA violations, significant financial penalties, reputational damage, and loss of patient trust for affected organizations.

## Recommendation

*   **Patch CVE-2026-24849**: Immediately upgrade OpenEMR instances to version 7.0.4 or higher to remediate CVE-2026-24849.
*   **Deploy Sigma Rules**: Implement the provided Sigma rules to your SIEM solution and configure web server logging (category `webserver`) to monitor for exploitation attempts.
*   **Monitor Web Server Logs**: Actively monitor `webserver` logs for requests to `/interface/modules/custom_modules/oe-module-faxsms/index.php` containing `_ACTION_COMMAND` and a `file_path` parameter, as detailed in the detection rules.
*   **Review Access Controls**: Periodically review and harden file system permissions on your OpenEMR deployment to follow the principle of least privilege, minimizing the impact even if a file read vulnerability is exploited.
