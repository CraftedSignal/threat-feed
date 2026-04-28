---
title: FlowiseAI File Upload Validation Bypass Leads to RCE
slug: 2026-04-17-flowise-upload-bypass
description: A file upload validation bypass vulnerability exists in FlowiseAI, where the Chatflow configuration file upload settings can be modified to allow the application/javascript MIME type, enabling an attacker to upload .js files, store malicious Node.js web shells on the server, and potentially achieve Remote Code Execution (RCE).
date: "2026-04-17T14:00:00Z"
type: coverage
types:
  - coverage
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

FlowiseAI, a low-code platform for building AI applications, contains a file upload validation bypass vulnerability. By modifying the Chatflow configuration, specifically the `allowedUploadFileTypes` setting, an attacker can add `application/javascript` as an accepted MIME type. This bypasses previous mitigations (CVE-2025-61687) intended to prevent the upload of potentially malicious files. Although the frontend UI restricts JavaScript uploads, a direct API request can circumvent this. Successful exploitation allows attackers to persistently store Node.js web shells (e.g., shell.js) on the Flowise server. This vulnerability affects FlowiseAI versions up to 3.0.13. If executed, these web shells could grant the attacker Remote Code Execution (RCE) capabilities on the server, posing a significant risk to system integrity and data confidentiality.

## Attack Chain

1.  The attacker identifies a vulnerable FlowiseAI instance running a version <= 3.0.13.
2.  The attacker authenticates to the FlowiseAI instance as an administrator or with compromised credentials.
3.  The attacker crafts a malicious HTTP PUT request to the `/api/v1/chatflows/{CHATFLOW_ID}` endpoint.
4.  The PUT request modifies the Chatflow configuration, specifically the `chatbotConfig` to include `application/javascript` in the `allowedUploadFileTypes`.
5.  The attacker crafts a malicious HTTP POST request to the `/api/v1/attachments/{CHATFLOW_ID}/{CHAT_ID}` endpoint to upload a `.js` file (Node.js web shell), such as the `shell.js` example.
6.  The server saves the malicious `.js` file to a publicly accessible directory.
7.  The attacker accesses the uploaded `.js` file via a direct HTTP request.
8.  The web shell executes commands specified in the URL parameters, such as `http://localhost:8888/?cmd=id`, resulting in RCE.

## Impact

Successful exploitation of this vulnerability allows attackers to upload and persistently store malicious web shells on the FlowiseAI server. Execution of these web shells grants the attacker the ability to execute arbitrary commands on the underlying system. This can lead to complete system compromise, data exfiltration, and denial of service. This vulnerability affects FlowiseAI versions up to 3.0.13.

## Recommendation

*   Apply appropriate input validation and sanitization to prevent modification of `allowedUploadFileTypes` settings.
*   Monitor network traffic for PUT requests to `/api/v1/chatflows/{CHATFLOW_ID}` modifying `allowedUploadFileTypes` as described in the attack chain.
*   Monitor for POST requests to `/api/v1/attachments/{CHATFLOW_ID}/{CHAT_ID}` uploading `.js` files based on the attack chain.
*   Deploy the Sigma rules provided below to detect suspicious HTTP requests indicative of this attack.
