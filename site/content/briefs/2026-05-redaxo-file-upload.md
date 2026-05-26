---
title: Redaxo CMS Mediapool Addon Arbitrary File Upload Vulnerability (CVE-2018-25353)
slug: 2026-05-redaxo-file-upload
description: Redaxo CMS Mediapool Addon version 5.5.1 and older contains an arbitrary file upload vulnerability (CVE-2018-25353) that allows authenticated users to bypass file extension blacklist restrictions, leading to arbitrary code execution.
date: "2026-05-26T13:42:11Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - file-upload
  - web-application
  - code-execution
vendors:
  - Redaxo
products:
  - Mediapool Addon
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
cves:
  - id: CVE-2018-25353
    cvss: 8.8
    epss: 0.00055
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-25353
  - https://redaxo.org
  - https://redaxo.org/download/redaxo/5.5.1.zip
  - https://www.exploit-db.com/exploits/44891
  - https://www.vulncheck.com/advisories/redaxo-cms-mediapool-addon-arbitrary-file-upload
rules:
  - title: Detects CVE-2018-25353 Exploitation — Suspicious File Extension Access in Redaxo Mediapool
    description: Detects CVE-2018-25353 exploitation — Access to files with suspicious extensions (e.g., php71, php53) within the Redaxo Mediapool directory.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1203
    data_sources:
      - webserver
  - title: Detects CVE-2018-25353 Attempt — Redaxo Mediapool File Upload with Suspicious Extension
    description: Detects CVE-2018-25353 attempt — File upload to Redaxo Mediapool directory with suspicious PHP-like extension in the filename.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
rules_count: 2
---

Redaxo CMS is a content management system written in PHP. The Mediapool Addon, up to version 5.5.1, suffers from an arbitrary file upload vulnerability (CVE-2018-25353). Authenticated users with editor privileges can bypass file extension blacklist restrictions implemented within the Mediapool functionality. By uploading files with double extensions or other obfuscated file extensions (e.g., php71, php53), attackers can circumvent the blacklist and upload malicious PHP files. This allows them to execute arbitrary code on the web server. This vulnerability was reported on May 23, 2026, and poses a significant threat to Redaxo CMS installations that have not been patched.

## Attack Chain

1. Attacker gains valid editor credentials for the Redaxo CMS.
2. Attacker logs into the Redaxo CMS administration panel.
3. Attacker navigates to the Mediapool section.
4. Attacker attempts to upload a malicious PHP file (e.g., webshell.php) through the Mediapool upload functionality.
5. The CMS checks the file extension against a blacklist.
6. To bypass the blacklist, the attacker renames the file with an obfuscated extension like "webshell.php71" or "webshell.php53".
7. The server accepts the file due to the bypassed extension check.
8. The attacker accesses the uploaded file through a direct HTTP request (e.g., `http://example.com/redaxo/media/webshell.php71`), triggering the execution of the malicious PHP code on the server.

## Impact

Successful exploitation of this vulnerability grants the attacker the ability to execute arbitrary PHP code on the Redaxo CMS web server. This can lead to complete compromise of the server, including data theft, website defacement, or further lateral movement within the network. Given that the vulnerable versions are relatively old, systems that have not been regularly updated are most at risk.

## Recommendation

*   Upgrade the Redaxo CMS Mediapool Addon to a version greater than 5.5.1 to patch CVE-2018-25353.
*   Implement stricter file extension validation on the server side, using a whitelist approach instead of a blacklist.
*   Monitor web server logs for requests to unusual file extensions in the Mediapool directory using the Sigma rule provided.
*   Implement the second Sigma rule to detect file uploads with suspicious extensions to the Mediapool.
