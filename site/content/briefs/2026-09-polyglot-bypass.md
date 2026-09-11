---
title: Detection of Web Server Polyglot File Upload Bypass
slug: 2026-09-polyglot-bypass
description: Detection of polyglot file creation by Linux web server processes, where file headers conflict with extensions, indicating potential web shell implantation or upload-validation bypass.
date: "2026-09-11T12:49:56Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - persistence
  - linux
  - web-server
  - web-shell
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: This rule identifies Linux web server processes creating files with script or executable extensions whose header bytes indicate a different format, which may expose an upload-validation bypass or concealed malicious payload.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker could upload a JPEG/PHP polyglot named avatar.php, pass image-type validation using valid JPEG header bytes, and later execute appended PHP code as a web shell.
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: This technique is a common method for attackers to bypass security measures and to hide the true nature of the file.
    confidence_band: med
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/persistence_webserver_file_polyglot_bypass.toml
rules:
  - title: Potential Polyglot Bypass File Created by Web Server
    description: Detects when a Linux web server process creates a file with a dangerous extension but header bytes that indicate a different file format, suggesting a polyglot upload-validation bypass.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable linux.advanced.events.populate_file_data in Elastic Agent policy.
      owner: Detection Engineering
      due: 48h
      evidence: Required for the rule to function.
  hunt_leads:
    - lead: Identify files with mismatched extensions and headers in web directories.
      technique_id: T1505.003
      data_needed:
        - File creation events in web server directories.
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Polyglot files indicate potential web shell activity.
  mitigation_plan:
    - priority: immediate
      action: Disable script execution in user-uploaded media directories.
      owner: IT Operations
      addresses: T1505.003
      evidence: Reduces risk of polyglot file execution.
---

This detection brief addresses the risk of polyglot file creation on Linux systems, a technique where attackers craft files that appear to be one data type based on header bytes (e.g., JPEG or PNG) but utilize a script extension (e.g., .php or .jsp) to bypass file upload validation. By successfully uploading a polyglot file, an attacker can bypass static validation checks that only verify the file header. If the web server subsequently processes the file or the directory is configured to execute scripts, the attacker can trigger embedded malicious code, resulting in a persistent web shell or remote command execution. This behavior is commonly associated with attackers exploiting public-facing applications and serves as a method for establishing persistent access or facilitating lateral movement. Defenders should monitor web server processes that create files with mismatched type signatures and extensions.

## Attack Chain

1. Attacker identifies a vulnerable file upload endpoint on a target web application.
2. Attacker crafts a malicious polyglot file, such as a JPEG containing hidden PHP code in the metadata or data payload.
3. Attacker sends an HTTP POST request containing the polyglot file to the server.
4. Web application security filter validates the file header bytes (e.g., JPEG Magic Bytes) and permits the upload.
5. The web server process writes the file to the local disk with an executable extension like .php.
6. Attacker triggers the execution of the file by navigating to its URI via a browser or HTTP client.
7. The web server interprets the embedded malicious code, resulting in code execution under the web server's context.
8. Attacker leverages the resulting web shell for persistence, exfiltration, or further lateral movement within the environment.

## Impact

Successful exploitation allows for unauthorized code execution, persistence, and potential escalation of privileges on the affected host. This may lead to the exfiltration of sensitive data, disruption of service, or further compromise of the internal network, depending on the permissions of the web server account.

## Recommendation

Prioritize the implementation of advanced file monitoring on all internet-facing Linux web servers to detect content/extension mismatches.

- Configure the Elastic Defend integration to set 'linux.advanced.events.populate_file_data' to 'true' to capture file extension and header information.
- Deploy the provided detection logic to identify processes commonly used in web hosting (e.g., nginx, apache2, php-fpm) that create files with mismatching extension/header pairs.
- Inspect files flagged by the detection logic for embedded script blocks or obfuscated code, and perform static analysis to confirm malicious intent.
- Harden application upload workflows by validating full file content (rather than relying on headers), renaming files upon upload, and storing uploaded media in directories configured to disable script execution.
