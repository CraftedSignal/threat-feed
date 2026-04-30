---
title: text-generation-webui Path Traversal Vulnerability (CVE-2026-35050)
slug: 2026-04-text-generation-webui-path-traversal
description: text-generation-webui versions prior to 4.1.1 are vulnerable to path traversal, allowing a high-privileged user to overwrite Python files and achieve arbitrary code execution by triggering the 'download-model.py' file through the application's 'Model' menu.
date: "2026-04-06T18:16:42Z"
severities:
  - critical
type: advisory
types:
  - advisory
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
iocs:
  - type: url
    value: https://github.com/oobabooga/text-generation-webui/security/advisories/GHSA-jg96-p5p6-q3cv
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

The text-generation-webui application, an open-source web interface for running Large Language Models, contains a path traversal vulnerability (CVE-2026-35050) in versions prior to 4.1.1. A high-privileged user can exploit this vulnerability by saving extension settings in ".py" format within the application's root directory. This allows them to overwrite existing Python files, most notably "download-model.py". Subsequently, the overwritten "download-model.py" file can be executed by initiating a new model download through the application's "Model" menu. Successful exploitation leads to arbitrary code execution within the context of the application. This vulnerability was patched in version 4.1.1.

## Attack Chain

1.  Attacker authenticates to the text-generation-webui application with high privileges.
2.  Attacker crafts a malicious Python script (e.g., containing reverse shell code).
3.  Attacker saves the malicious script as an extension setting in ".py" format, leveraging path traversal to target the application's root directory. The filename is chosen to overwrite "download-model.py".
4.  The application saves the malicious ".py" file, overwriting the original "download-model.py" in the application root.
5.  Attacker navigates to the "Model" menu within the text-generation-webui.
6.  Attacker initiates the download of a new model, triggering the execution of the (now compromised) "download-model.py" file.
7.  The malicious Python code within "download-model.py" executes, granting the attacker arbitrary code execution on the server.
8.  The attacker establishes a reverse shell connection to their controlled system, achieving full system compromise.

## Impact

Successful exploitation of CVE-2026-35050 allows a high-privileged attacker to achieve arbitrary code execution on the server hosting the text-generation-webui application. This could lead to complete system compromise, data exfiltration, and denial of service. The impact is critical due to the ease of exploitation and the potential for significant damage. Organizations using vulnerable versions of text-generation-webui are at risk of having their systems compromised.

## Recommendation

*   Immediately upgrade text-generation-webui to version 4.1.1 or later to patch CVE-2026-35050.
*   Implement strict file permission controls to prevent unauthorized modification of critical application files, mitigating similar path traversal vulnerabilities.
*   Monitor web server logs for unusual file creation events in the application root directory to detect potential exploitation attempts (see example Sigma rule below targeting file creation in the webserver category).
*   Inspect network connections originating from the text-generation-webui server for suspicious outbound connections, which could indicate a reverse shell or other malicious activity resulting from code execution. Deploy the provided Sigma rule to detect such connections.
