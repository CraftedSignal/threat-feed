---
brief_id: brief-2026-10-23-linux-wget-exfiltration
event_id: brief-2026-10-23-linux-wget-exfiltration
revision: 1
activity_at: "2026-10-23T14:39:13Z"
title: 'Linux: Potential Data Exfiltration via Wget Utility'
slug: 2026-10-linux-wget-exfiltration
description: Attackers utilize the wget utility with post-upload flags to exfiltrate staged local data to external servers, a technique observable through process creation monitoring.
date: "2026-10-23T14:39:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - exfiltration
  - linux
  - wget
  - endpoint-security
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: Detects the use of wget to upload files to an internet server.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Threat actors often will collect data on a system and attempt to exfiltrate it back to their command and control servers.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/linux/exfiltration_potential_wget_data_exfiltration.toml
  - https://gtfobins.github.io/gtfobins/wget/
rules:
  - title: Detect Potential Data Exfiltration via Wget
    description: Detects the use of wget with post-upload flags or suspicious command-line piping of sensitive files to remote web endpoints.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1005
      - T1048
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
    - action: Deploy the provided detection rule to monitor process executions for wget upload flags.
      owner: Detection Engineering
      due: 48h
      evidence: Rule definition provided in source
  hunt_leads:
    - lead: Search for recent command line activity containing wget and POST-related flags.
      technique_id: T1048
      data_needed:
        - Process command line history
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Attackers gather files... then execute wget --post-file
  mitigation_plan:
    - priority: medium
      action: Implement Egress proxy filtering for HTTP POST requests.
      owner: IT Operations
      addresses: Exfiltration over HTTP/HTTPS
      evidence: Hardening recommendation in source
---

Data exfiltration activity on Linux systems is often conducted by staging files in directories such as /tmp and utilizing the wget utility to push these files to remote servers via HTTP POST requests. This activity frequently originates from non-interactive shell sessions or automated tasks like cron jobs. While wget is a legitimate networking tool, the use of upload-specific flags when interacting with external web resources is highly suspicious and warrants immediate investigation.

## Attack Chain
1. Collection: The attacker identifies and accesses sensitive data, such as credentials, configuration files, or user archives.
2. Staging: Collected files are compressed or moved to a directory, commonly /tmp, /var/tmp, or user home directories, to prepare for exfiltration.
3. Execution: The attacker initiates an outbound connection using wget with POST-capable flags (e.g., --post-file, --body-file).
4. Exfiltration: Data is transmitted via HTTP/HTTPS to an external command-and-control server.

## Impact
Unauthorized exfiltration of sensitive information, including credentials, source code, and customer data, potentially leading to long-term persistence, further network compromise, or data exposure.

## Recommendation
- Deploy detection rules to identify suspicious execution of wget with file-upload arguments.
- Audit cron jobs, systemd services, and scheduled tasks to identify unauthorized scripts containing wget upload commands.
- Implement egress filtering to restrict HTTP POST requests to known, approved destinations.
- Restrict the execution of wget to only authorized users and processes via filesystem permissions or application allowlisting.
