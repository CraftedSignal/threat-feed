---
title: Detection of Suspicious Web Server Child Processes on Linux
slug: 2026-08-linux-webshell-indicators
description: This brief provides detection logic to identify potential webshell activity on Linux systems by monitoring for suspicious child processes spawned by common web server applications.
date: "2026-08-18T23:52:27Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - linux
  - web-server
  - detection-engineering
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: Server Software Component
    evidence: Detects suspicious sub processes of web server processes
    confidence_band: high
rules:
  - title: Detect Suspicious Linux Web Server Child Processes
    description: Detects suspicious sub-processes spawned by common web server processes indicating potential webshell activity.
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
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for suspicious process lineage
      owner: Detection Engineering
      due: 72h
      evidence: Source provides specific process paths indicative of webshell activity
  mitigation_plan:
    - priority: short_term
      action: Review web server user permissions and restrict execution of unnecessary binaries
      owner: IT Operations
      addresses: T1505.003
      evidence: Standard security hardening for web servers
---

Webshells are commonly used by attackers to maintain persistence and execute commands on compromised web servers. On Linux systems, a strong indicator of compromise is the execution of system administration or reconnaissance tools directly from the web server process (e.g., Apache, Nginx, Node.js). This brief codifies detection logic for identifying when web server parent processes spawn unauthorized child processes, such as 'whoami', 'ifconfig', 'crontab', or network configuration utilities. Defenders should monitor for these patterns to detect unauthorized command execution following initial access or exploit staging. This detection method focuses on process lineage tracking to identify deviations from normal web application behavior.

## Impact

Successful exploitation can lead to unauthorized code execution, system reconnaissance, and persistent backdoors on the affected web infrastructure. This pattern helps identify incidents ranging from web-based vulnerability exploitation to post-exploitation lateral movement attempts.

## Recommendation

Deploy the provided Sigma rule to your SIEM to monitor for unauthorized sub-process spawning from web server applications. Tune the rule by white-listing legitimate application-specific execution paths to reduce false positives associated with complex web applications that require OS-level utility access.
