---
title: Detection of Web Server Access Log Deletion
slug: 2026-09-websvr-log-deletion
description: Adversaries often delete web server access logs to destroy forensic evidence and evade detection after unauthorized activity, a behavior monitorable through file deletion events on common web server log paths.
date: "2026-09-18T19:09:28Z"
lastmod: "2026-09-19T13:11:06Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - defense-evasion
  - file-integrity
  - logs
  - cross-platform
vendors:
  - Apache
  - Microsoft
products:
  - HTTP Server
  - IIS
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1070
    technique_name: Indicator Removal
    evidence: Adversaries may delete these logs to cover their tracks, hindering forensic investigations.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/defense_evasion_deleting_websvr_access_logs.toml
rules:
  - title: Detect Web Server Access Log Deletion
    description: Detects the deletion of web server access logs, which may indicate an attempt to evade detection or destroy forensic evidence.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1070.004
    data_sources:
      - file_event
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy file deletion detection rule to SIEM
      owner: Detection Engineering
      due: 48h
  hunt_leads:
    - lead: Search for instances of log files being deleted followed by unusual system activity
      technique_id: T1070.004
      disposition: convert_to_detection
  mitigation_plan:
    - priority: short_term
      action: Review and restrict write/delete permissions on web server log directories
      owner: IT Operations
updates:
  - at: "2026-09-19T13:11:06Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/defense_evasion_deleting_websvr_access_logs.toml
---

Adversaries frequently target web server access logs during the post-exploitation phase to cover their tracks and impede incident response. By deleting these files, attackers aim to destroy records of their initial access, C2 communication, or internal reconnaissance activities. This behavior is cross-platform, affecting common web server architectures including Microsoft IIS, Apache, and HTTPd. Detection engineering teams should monitor for file deletion events occurring within standard directory paths dedicated to log storage. While this activity is often malicious, defenders must differentiate between attacker-led indicator removal and routine administrative tasks such as log rotation, automated backups, or environment resets.

## Attack Chain

1. Attacker gains unauthorized access to a web server via exploit or credential misuse.
2. Attacker executes commands to explore the file system and locate web server log directories.
3. Attacker identifies the specific log files that record their malicious activities.
4. Attacker issues delete commands (e.g., 'del' on Windows or 'rm' on Linux/macOS) to target the log files.
5. The OS records a 'file deletion' event within the EDR or system logging subsystem.
6. Security tools trigger an alert based on the file path matching web server log conventions.
7. Attacker continues unauthorized activity with reduced visibility for responders.

## Impact

Successful deletion of web server access logs results in the permanent loss of critical forensic data required for determining the scope of a breach, identifying the attacker's IP address, and mapping the timeline of an incident. Without these logs, defenders may be unable to confirm if sensitive data was exfiltrated or which specific web application vulnerabilities were exploited, forcing a reliance on secondary, potentially less reliable telemetry.

## Recommendation

* Deploy the detection rule below to identify unauthorized file deletion events targeting web server logs.
* Establish a baseline of authorized log rotation processes, backup scripts, and maintenance tasks; use these as filters to reduce noise.
* Audit access controls on web server log directories to restrict write and delete permissions to service accounts and authorized administrative roles only.
* Correlate log deletion alerts with preceding web server requests or unauthorized process executions to confirm malicious intent.
