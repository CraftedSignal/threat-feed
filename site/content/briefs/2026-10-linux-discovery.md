---
title: Detection of Linux File and Directory Discovery via Auditd
slug: 2026-10-linux-discovery
description: This detection identifies suspicious reconnaissance activity on Linux systems where utilities like find or grep are used to locate sensitive document files, a technique commonly used by attackers for data identification and exfiltration.
date: "2026-10-12T17:47:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - discovery
  - linux
  - reconnaissance
  - auditd
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: The analytic detects suspicious file and directory discovery activities, which may indicate an attacker's effort to locate sensitive documents and files on a compromised system.
    confidence_band: high
rules:
  - title: Detect Linux File and Directory Discovery
    description: Detects the use of find or grep to discover files with extensions commonly associated with sensitive documents.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1083
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for file enumeration
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific command patterns for detection
  hunt_leads:
    - lead: Search for high volumes of file enumeration commands from service accounts
      technique_id: T1083
      data_needed:
        - process_creation logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Source mentions administrator/automation usage as a source of false positives
---

Adversaries often perform discovery operations to locate sensitive data after gaining access to a Linux system. This activity involves using native command-line utilities such as `find` or `grep` to scan the filesystem for specific file extensions that indicate the presence of documents, images, or archives. By identifying these files, attackers can prioritize their efforts for data theft or identify credentials and configuration files that aid in further privilege escalation. Monitoring for the combination of search utilities and specific sensitive file patterns allows defenders to identify reconnaissance behavior that precedes more destructive stages of an attack, such as data exfiltration or credential harvesting.

## Attack Chain

1. Attacker gains initial access or escalation to a Linux endpoint.
2. Attacker establishes a shell session (e.g., via SSH or a web shell).
3. Attacker identifies the need to locate sensitive user documents or configuration files.
4. Attacker executes search commands (e.g., `find / -name "*.pdf"`) to enumerate the filesystem.
5. Attacker iterates through the discovered paths to verify the content of interest.
6. Attacker compresses or stages the located files for staging.
7. Attacker exfiltrates the staged data to an external command-and-control server.

## Impact

Successful file discovery significantly lowers the time required for an attacker to locate high-value information, increasing the risk of data breaches and exposure of confidential intellectual property or personal identifiable information (PII).

## Recommendation

* Deploy the provided Sigma rule to your SIEM to monitor for reconnaissance activity involving sensitive file extensions.
* Integrate Linux Auditd (SYSCALL, EXECVE events) into your SIEM pipeline and use the Splunk Add-on for Unix and Linux for standardized parsing.
* Tune the detection logic for your environment by excluding authorized administrative scripts or automated backup tasks that perform recursive file searches.
