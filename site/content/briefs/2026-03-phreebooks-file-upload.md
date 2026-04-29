---
title: PhreeBooks ERP 5.2.3 Arbitrary File Upload Vulnerability
slug: 2026-03-phreebooks-file-upload
description: PhreeBooks ERP 5.2.3 is vulnerable to arbitrary file upload in the Image Manager component, allowing authenticated attackers to upload malicious PHP files leading to remote code execution.
date: "2026-03-24T12:16:03Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - phreebooks
  - file-upload
  - rce
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25630
  - https://www.vulncheck.com/advisories/phreebooks-erp-arbitrary-file-upload-via-image-manager
rules:
  - title: Phreebooks Image Upload
    description: Detects attempts to upload PHP files to the Phreebooks image manager
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Phreebooks bizunoFS.php Execution
    description: Detects access to the bizunoFS.php file, which may indicate RCE after a file upload.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - webserver
      - linux
rules_count: 2
---

PhreeBooks ERP version 5.2.3 contains a critical arbitrary file upload vulnerability within its Image Manager component. This vulnerability allows authenticated attackers to bypass security restrictions and upload malicious files to the server. By crafting specific requests to the image upload endpoint, threat actors can inject PHP files. The successful exploitation of this vulnerability allows for arbitrary code execution on the underlying system, potentially leading to full system compromise. This issue was reported and assigned CVE-2019-25630. Successful exploitation requires authentication, limiting the scope of easily exploitable targets. However, the impact of successful exploitation is severe, allowing for complete control of the affected PhreeBooks ERP instance.

## Attack Chain

1.  The attacker authenticates to the PhreeBooks ERP 5.2.3 application.
2.  The attacker navigates to the Image Manager component.
3.  The attacker crafts a malicious HTTP POST request to the `bizuno/image/manager` endpoint.
4.  The request includes the `imgFile` parameter containing a PHP file disguised as an image (e.g., using a double extension like `evil.php.jpg`).
5.  The server saves the uploaded file to a publicly accessible directory.
6.  The attacker then accesses the uploaded PHP file via a direct HTTP request to `/bizunoFS.php`.
7.  The `bizunoFS.php` script executes the malicious PHP code.
8.  The attacker gains remote code execution on the server, enabling further malicious activities like data exfiltration or system compromise.

## Impact

Successful exploitation of this vulnerability allows an attacker to execute arbitrary code on the PhreeBooks ERP server. This can lead to complete compromise of the server, including data exfiltration, modification of financial records, and denial of service. While the number of affected installations is unknown, the potential impact on compromised systems is significant due to the sensitive data typically managed by ERP systems. Organizations using PhreeBooks ERP 5.2.3 are vulnerable to complete data loss, financial fraud, and reputational damage.

## Recommendation

*   Apply available patches or upgrade to a secure version of PhreeBooks ERP to remediate CVE-2019-25630.
*   Implement the Sigma rule `Phreebooks Image Upload` to detect suspicious requests to the `bizuno/image/manager` endpoint.
*   Monitor web server logs for access to PHP files within the image upload directories, as this can be a sign of successful exploitation via `bizunoFS.php`.
*   Implement input validation on the server side to prevent uploading files with dangerous extensions like `.php`.
