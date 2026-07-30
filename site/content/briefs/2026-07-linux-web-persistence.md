---
title: Detection of Unusual File Creation by Web Server Processes on Linux
slug: 2026-07-linux-web-persistence
description: This brief details a behavioral detection strategy for identifying potential web shell deployment and persistence mechanisms by monitoring anomalous file creation activities originating from common web server processes on Linux.
date: "2026-07-30T13:32:31Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - persistence
  - web-shell
  - linux
  - behavioral-detection
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Attackers may exploit web servers to maintain persistence on a compromised system, often resulting in atypical file creations.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers may exploit web servers to maintain persistence on a compromised system, often resulting in atypical file creations.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: The detection helps identify file creations used by attackers to establish command and control.
    confidence_band: med
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers often exploit public-facing web applications to write malicious files.
    confidence_band: high
rules:
  - title: Unusual File Creation via Web Server
    description: Detects anomalous file creation or renaming events initiated by web server processes in sensitive web directories, indicating potential web shell deployment.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

Attackers frequently target public-facing web applications to establish persistence, execute commands, or facilitate command-and-control communication. A common technique involves exploiting a vulnerability to write malicious scripts (such as web shells or backdoored application components) to web-accessible directories. Because web servers legitimatey create and modify files (e.g., during deployments, session management, or cache updates), static detection often leads to high false-positive rates.

This detection approach focuses on identifying deviations from established baseline behavior. By utilizing new term detection (comparing current file creation events against historical data over a seven-day window), defenders can flag anomalous file creation actions initiated by various web server processes, including Nginx, Apache, PHP-FPM, Java, and Node.js. This monitoring targets sensitive directories such as web roots, upload folders, and temporary storage locations where attackers typically land their malicious payloads.

## Attack Chain

1. Attacker identifies a vulnerability (e.g., unauthenticated file upload, path traversal, or remote code execution) in a public-facing web application.
2. Attacker crafts a malicious payload, such as a PHP, JSP, or ASPX web shell.
3. Attacker sends an HTTP request to the vulnerable endpoint to trigger the writing of the malicious file to the disk.
4. The web server process (e.g., php-fpm, nginx, or java) performs the write operation in the target directory (e.g., /var/www/html/uploads/shell.php).
5. The file is successfully written, and the attacker verifies its existence.
6. Attacker initiates an HTTP request to the newly created file to execute system-level commands through the web shell.
7. The web server interprets the file and executes the embedded code, granting the attacker a persistent foothold.

## Impact

Successful exploitation allows attackers to gain unauthorized remote code execution, bypass authentication, exfiltrate sensitive data, and maintain persistent access to the compromised server. This can lead to full system compromise, lateral movement within the network, and the deployment of additional malware, such as ransomware or data exfiltrators.

## Recommendation

Deploy behavioral monitoring to baseline and detect anomalous file creation patterns from web server processes:
- Implement monitoring for the specific file paths identified in the query, including web roots and application upload directories.
- Utilize the provided detection logic to alert on deviations from historical activity in your SIEM environment.
- Audit all files created within web directories by server processes for unauthorized scripts or unexpected file extensions.
- Restrict write permissions for web server service accounts to the minimum required directories to prevent unauthorized file placement.
