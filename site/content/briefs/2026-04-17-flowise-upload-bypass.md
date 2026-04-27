---
title: FlowiseAI File Upload Validation Bypass Leads to RCE
slug: 2026-04-17-flowise-upload-bypass
description: A file upload validation bypass vulnerability exists in FlowiseAI, where the Chatflow configuration file upload settings can be modified to allow the application/javascript MIME type, enabling an attacker to upload .js files, store malicious Node.js web shells on the server, and potentially achieve Remote Code Execution (RCE).
date: "2026-04-17T14:00:00Z"
severities:
  - critical
tags:
  - flowiseai
  - file-upload
  - rce
  - web-shell
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2025-61687
    cvss: 8.3
    epss: 0.00178
references:
  - https://github.com/advisories/GHSA-rh7v-6w34-w2rr
rules:
  - title: FlowiseAI Chatflow Configuration Modification
    description: Detects modification of Chatflow configuration to allow JavaScript MIME type, indicating potential file upload bypass.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: FlowiseAI JavaScript File Upload Attempt
    description: Detects attempts to upload JavaScript files to FlowiseAI attachments endpoint.
    platform: sigma
    severity: high
    tactics:
      - execution
      - persistence
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

FlowiseAI, a low-code platform for building AI applications, contains a file upload validation bypass vulnerability. By modifying the Chatflow configuration, specifically the `allowedUploadFileTypes` setting, an attacker can add `application/javascript` as an accepted MIME type. This bypasses previous mitigations (CVE-2025-61687) intended to prevent the upload of potentially malicious files. Although the frontend UI restricts JavaScript uploads, a direct API request can circumvent this…
