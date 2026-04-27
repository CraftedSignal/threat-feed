---
title: text-generation-webui Path Traversal Vulnerability (CVE-2026-35050)
slug: 2026-04-text-generation-webui-path-traversal
description: text-generation-webui versions prior to 4.1.1 are vulnerable to path traversal, allowing a high-privileged user to overwrite Python files and achieve arbitrary code execution by triggering the 'download-model.py' file through the application's 'Model' menu.
date: "2026-04-06T18:16:42Z"
severities:
  - critical
tags:
  - path traversal
  - code execution
  - text-generation-webui
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
cves:
  - id: CVE-2026-35050
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-35050
  - https://github.com/oobabooga/text-generation-webui/security/advisories/GHSA-jg96-p5p6-q3cv
ioc_counts:
  url: 1
rules:
  - title: Detect File Creation in Web Application Root Directory
    description: Detects file creation events within web application root directories, potentially indicating path traversal exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - file_event
      - linux
  - title: Detect Suspicious Outbound Connections from text-generation-webui
    description: Detects outbound network connections from the text-generation-webui application that may indicate a reverse shell or other malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

The text-generation-webui application, an open-source web interface for running Large Language Models, contains a path traversal vulnerability (CVE-2026-35050) in versions prior to 4.1.1. A high-privileged user can exploit this vulnerability by saving extension settings in ".py" format within the application's root directory. This allows them to overwrite existing Python files, most notably "download-model.py". Subsequently, the overwritten "download-model.py" file can be executed by initiating…
