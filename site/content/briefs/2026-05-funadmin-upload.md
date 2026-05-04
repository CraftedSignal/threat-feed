---
title: Funadmin Unrestricted File Upload Vulnerability (CVE-2026-7733)
slug: 2026-05-funadmin-upload
description: Funadmin versions up to 7.1.0-rc6 are vulnerable to unrestricted file uploads due to improper handling of the File argument in the UploadService::chunkUpload function, potentially leading to remote code execution.
date: "2026-05-04T06:16:02Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve
  - unrestricted file upload
  - remote code execution
vendors:
  - funadmin
products:
  - funadmin <= 7.1.0-rc6
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-7733
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7733
  - https://gitee.com/funadmin/funadmin/
  - https://gitee.com/funadmin/funadmin/issues/IJ8NXT
  - https://gitee.com/funadmin/funadmin/pulls/59
  - https://vuldb.com/submit/807559
  - https://vuldb.com/vuln/360908
  - https://vuldb.com/vuln/360908/cti
rules:
  - title: Detect Funadmin Unrestricted File Upload Attempt (CVE-2026-7733)
    description: Detects attempts to exploit the unrestricted file upload vulnerability in Funadmin via suspicious requests to the chunk upload endpoint.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Funadmin Unrestricted File Upload Attempt via Filename
    description: Detects attempts to exploit the unrestricted file upload vulnerability in Funadmin by checking filename for suspicious extensions in the request.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

Funadmin, a web framework, is vulnerable to an unrestricted file upload vulnerability (CVE-2026-7733) affecting versions up to 7.1.0-rc6. The vulnerability exists within the `UploadService::chunkUpload` function in the `app/common/service/UploadService.php` file, which handles frontend chunked uploads. An attacker can manipulate the `File` argument during the upload process to bypass security checks and upload arbitrary files. The vulnerability is remotely exploitable, and an exploit has been published. Patch 59 is available to remediate this vulnerability. This issue enables attackers to upload malicious files, such as web shells or executable code, leading to potential remote code execution on the affected server.

## Attack Chain

1.  The attacker identifies a Funadmin instance running a vulnerable version (<= 7.1.0-rc6).
2.  The attacker sends a crafted HTTP request to the `UploadService::chunkUpload` endpoint.
3.  The request includes a manipulated `File` argument, bypassing file type and size restrictions.
4.  The vulnerable `UploadService::chunkUpload` function processes the malicious file without proper validation.
5.  The malicious file is written to the server's file system in a publicly accessible directory.
6.  The attacker accesses the uploaded file, potentially triggering execution (e.g., accessing a PHP web shell).
7.  If the uploaded file is executable code (webshell), the attacker can execute arbitrary commands on the server.
8.  The attacker gains control of the web server and potentially pivots to other systems within the network.

## Impact

Successful exploitation of this vulnerability allows an attacker to upload arbitrary files to the Funadmin server. This can lead to several severe consequences, including remote code execution, web server defacement, data exfiltration, and complete system compromise. Given the ease of exploitation (an exploit is publicly available), affected systems are at high risk of being targeted. Organizations using vulnerable versions of Funadmin should apply patch 59 immediately to prevent potential attacks.

## Recommendation

*   Apply patch 59 to all Funadmin installations running versions up to 7.1.0-rc6 as recommended by the vendor.
*   Monitor web server logs for unusual activity related to file uploads, specifically requests targeting the `UploadService::chunkUpload` endpoint (reference: Attack Chain).
*   Deploy the Sigma rule provided to detect attempts to exploit CVE-2026-7733 by monitoring for requests to the vulnerable endpoint with suspicious parameters.
*   Implement web application firewall (WAF) rules to filter out requests with malicious payloads targeting the `UploadService::chunkUpload` endpoint (reference: Attack Chain).
