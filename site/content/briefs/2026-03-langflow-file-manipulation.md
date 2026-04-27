---
title: Langflow Vulnerability Allows File Manipulation
slug: 2026-03-langflow-file-manipulation
description: An authenticated, remote attacker can exploit a vulnerability in Langflow to manipulate files, potentially leading to unauthorized data modification or application compromise.
date: "2026-03-30T10:16:46Z"
severities:
  - high
tags:
  - langflow
  - file-manipulation
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0868
rules:
  - title: Detect File Modification within Langflow Directory
    description: Detects file modifications within the Langflow application directory, which may indicate exploitation of the file manipulation vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - file_event
      - linux
  - title: Detect Creation of Executable Files in Langflow Directory
    description: Detects the creation of executable files within the Langflow application directory, which could indicate an attacker uploading malicious code.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists in Langflow that allows a remote, authenticated attacker to manipulate files. Langflow is a UI for rapidly prototyping flows. The specific nature of the vulnerability is not detailed in the source document, but the impact is that an attacker with valid credentials can modify files accessible to the Langflow application. This could potentially lead to code injection, data corruption, or unauthorized access to sensitive information within the application's scope. Defenders…
