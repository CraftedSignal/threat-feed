---
title: PhreeBooks ERP 5.2.3 Arbitrary File Upload Vulnerability
slug: 2026-03-phreebooks-file-upload
description: PhreeBooks ERP 5.2.3 is vulnerable to arbitrary file upload in the Image Manager component, allowing authenticated attackers to upload malicious PHP files leading to remote code execution.
date: "2026-03-24T12:16:03Z"
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

PhreeBooks ERP version 5.2.3 contains a critical arbitrary file upload vulnerability within its Image Manager component. This vulnerability allows authenticated attackers to bypass security restrictions and upload malicious files to the server. By crafting specific requests to the image upload endpoint, threat actors can inject PHP files. The successful exploitation of this vulnerability allows for arbitrary code execution on the underlying system, potentially leading to full system compromise…
