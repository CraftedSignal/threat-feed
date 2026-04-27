---
title: phpBB Arbitrary File Upload Vulnerability (CVE-2019-25685)
slug: 2026-04-phpbb-file-upload
description: phpBB is vulnerable to arbitrary file upload (CVE-2019-25685) by exploiting the plupload functionality and phar:// stream wrapper, allowing authenticated attackers to upload crafted zip files containing serialized PHP objects that execute arbitrary code via the imagick parameter.
date: "2026-04-05T21:16:47Z"
severities:
  - critical
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

CVE-2019-25685 is an arbitrary file upload vulnerability affecting phpBB. An authenticated attacker can exploit this vulnerability to upload malicious files by leveraging the plupload functionality and the phar:// stream wrapper. This allows them to upload a crafted ZIP archive that includes serialized PHP objects, leading to arbitrary code execution when these objects are deserialized via the imagick parameter within the attachment settings. Successful exploitation can result in complete…
