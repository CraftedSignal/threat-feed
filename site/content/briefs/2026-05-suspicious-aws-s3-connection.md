---
title: Suspicious AWS S3 Connection via Script Interpreter
slug: 2026-05-suspicious-aws-s3-connection
description: The rule detects script interpreters (osascript, Node.js, Python) making outbound connections to AWS S3 or CloudFront domains on macOS, which may indicate command and control or data exfiltration activity.
date: "2026-05-25T06:36:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - command-and-control
  - exfiltration
  - macos
vendors:
  - Amazon
products:
  - AWS S3
  - CloudFront
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1102
    technique_name: Web Service
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/macos/command_and_control_aws_s3_connection_via_script.toml
rules:
  - title: macOS Suspicious AWS S3 Connection via Script Interpreter
    description: Detects macOS script interpreters (osascript, Node.js, Python) initiating multiple outbound connections to AWS S3 or CloudFront domains, potentially indicating command and control or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
      - exfiltration
    techniques:
      - T1059
      - T1102
      - T1567.002
    data_sources:
      - network_connection
      - macos
  - title: macOS Script Interpreter Connecting to AWS S3 - Low Volume
    description: Detects macOS script interpreters (osascript, Node.js, Python) initiating connections to AWS S3 or CloudFront domains. This rule is for environments with low traffic to AWS resources.
    platform: sigma
    severity: low
    tactics:
      - command_and_control
      - execution
      - exfiltration
    techniques:
      - T1059
      - T1102
      - T1567.002
    data_sources:
      - network_connection
      - macos
rules_count: 2
---

This rule detects when a script interpreter (osascript, Node.js, Python) with minimal arguments makes an outbound connection to AWS S3 or CloudFront domains on macOS. Threat actors have been observed using S3 buckets for both command and control and data exfiltration. This detection focuses on identifying script interpreters connecting to cloud storage that warrant investigation for potential malicious activity. The rule triggers when a script interpreter establishes a high number of connections (>= 20) to AWS S3 or CloudFront, suggesting automated or scripted behavior rather than normal application traffic.

## Attack Chain

1.  A user executes a script interpreter (osascript, node, python) on a macOS system.
2.  The script contains code to interact with AWS S3 or CloudFront.
3.  The script establishes a network connection to an AWS S3 bucket (s3.*.amazonaws.com or *.s3*.amazonaws.com) or a CloudFront domain (*.cloudfront.net).
4.  The script retrieves a second-stage payload or configuration from the S3 bucket or CloudFront distribution.
5.  The script polls the same S3 bucket or CloudFront-backed URL for commands at regular intervals.
6.  Alternatively, the script uploads stolen data to the S3 bucket using multipart upload patterns.
7.  The attacker uses the S3 bucket for command and control or data exfiltration.

## Impact

A successful attack could lead to data exfiltration or remote command execution on the compromised macOS system. The attacker can use the S3 bucket to store stolen data or to control the compromised system, potentially leading to further damage. Since the rule triggers on a high number of connections (>=20), it indicates potentially automated behavior.

## Recommendation

*   Deploy the Sigma rule `macOS Suspicious AWS S3 Connection via Script Interpreter` to your SIEM and tune the threshold (connection_count >= 20) for your environment.
*   Investigate any alerts triggered by the Sigma rule, focusing on the process ancestry, command-line arguments, and associated network connections.
*   Review concurrent endpoint activity from the same process and user, such as file downloads to writable/temp locations, new executable creation, permission changes, or immediate execution of newly written payloads.
*   Monitor network traffic for unusually large outbound byte counts, multipart upload patterns, and matching connections from other hosts using the same domain.
