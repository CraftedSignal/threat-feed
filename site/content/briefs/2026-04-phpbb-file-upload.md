---
title: phpBB Arbitrary File Upload Vulnerability (CVE-2019-25685)
slug: 2026-04-phpbb-file-upload
description: phpBB is vulnerable to arbitrary file upload (CVE-2019-25685) by exploiting the plupload functionality and phar:// stream wrapper, allowing authenticated attackers to upload crafted zip files containing serialized PHP objects that execute arbitrary code via the imagick parameter.
date: "2026-04-05T21:16:47Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - phpBB
  - file-upload
  - deserialization
  - CVE-2019-25685
cves:
  - id: CVE-2019-25685
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25685
  - https://www.exploit-db.com/exploits/46512
  - https://www.vulncheck.com/advisories/phpbb-arbitrary-file-upload-via-phar-deserialization
rules:
  - title: phpBB Phar Upload Attempt
    description: Detects attempts to upload files using the phar:// stream wrapper in phpBB, indicating a potential exploit of CVE-2019-25685.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    data_sources:
      - webserver
      - linux
  - title: phpBB Suspicious File Creation
    description: Detects the creation of suspicious files (e.g., PHP scripts) within the phpBB file upload directories, potentially indicating successful exploitation of a file upload vulnerability.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2019-25685 is an arbitrary file upload vulnerability affecting phpBB. An authenticated attacker can exploit this vulnerability to upload malicious files by leveraging the plupload functionality and the phar:// stream wrapper. This allows them to upload a crafted ZIP archive that includes serialized PHP objects, leading to arbitrary code execution when these objects are deserialized via the imagick parameter within the attachment settings. Successful exploitation can result in complete server compromise, allowing the attacker to execute arbitrary commands, potentially leading to data theft, website defacement, or denial of service.

## Attack Chain

1.  The attacker authenticates to the phpBB application.
2.  The attacker crafts a malicious ZIP archive containing serialized PHP objects designed for remote code execution. This archive is designed to be processed by the `phar://` stream wrapper.
3.  The attacker uploads the crafted ZIP archive through the plupload functionality, potentially disguised as a legitimate attachment type.
4.  The phpBB application processes the uploaded file. The application uses the phar:// stream wrapper to extract the contents of the uploaded ZIP file.
5.  The application deserializes the malicious PHP objects, triggered by the imagick parameter in attachment settings.
6.  Deserialization of the crafted PHP objects leads to arbitrary code execution on the server.
7.  The attacker gains control of the web server, potentially escalating privileges.

## Impact

Successful exploitation of CVE-2019-25685 allows an attacker to execute arbitrary code on the phpBB server. The attacker could gain complete control of the web server, potentially leading to data theft, website defacement, or denial of service. The impact is significant due to the potential for full system compromise. The number of victims is dependent on the number of phpBB installations exposed and targeted.

## Recommendation

*   Inspect web server logs for POST requests to attachment upload endpoints containing ZIP archives and the "phar://" wrapper in request parameters to detect potential exploit attempts. (Log Source: webserver, Rule: phpbb_phar_upload)
*   Monitor phpBB file upload directories for the creation of unexpected files, particularly PHP scripts or other executable files. (Log Source: file_event, Rule: phpbb_suspicious_file_creation)
*   Apply available patches or updates for phpBB to address CVE-2019-25685 as soon as possible.
