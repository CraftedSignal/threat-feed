---
title: Wiz Runtime Sensor Provides Threat Detection for Google Cloud Run Containers
slug: 2026-05-google-cloud-run-runtime-threat-detection
description: Wiz's Runtime Sensor for Google Cloud Run Containers offers real-time threat detection and response for serverless container workloads by monitoring process execution, system calls, and runtime behavior to detect unauthorized activity, correlate events into consolidated threats, and enable automated responses.
date: "2026-05-19T14:24:23Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - runtime-security
  - threat-detection
vendors:
  - Google
  - Wiz
products:
  - Cloud Run
  - Wiz Runtime Sensor
  - Wiz Blue Agent
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: Command and Scripting Interpreter
references:
  - https://www.wiz.io/blog/introducing-runtime-threat-detection-for-google-cloud-run
rules:
  - title: Detect Reverse Shell Activity in Google Cloud Run Containers
    description: Detects reverse shell activity within Google Cloud Run containers, indicating potential attacker command and control.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Execution of Unknown Binaries in Google Cloud Run
    description: Detects execution of binaries within Google Cloud Run containers that were not present in the original image, indicating suspicious or malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - linux
  - title: Detect DNS Queries to Known Malicious Domains
    description: Detects DNS queries to known malicious domains from Google Cloud Run containers, indicating potential command-and-control or data exfiltration.
    platform: sigma
    severity: high
    tactics:
      - command_and_control
    techniques:
      - T1568.002
    data_sources:
      - dns_query
      - linux
rules_count: 3
---

Wiz has announced the general availability of its Runtime Sensor for Google Cloud Run Containers, providing real-time threat detection and response capabilities for serverless container workloads. Google Cloud Run is a popular platform for deploying containerized applications without managing infrastructure. As Cloud Run adoption increases, security teams face the challenge of detecting threats and malicious activities inside running containers. The Wiz Runtime Sensor provides continuous, real-time visibility into container execution, enabling investigation with the Wiz Blue Agent and automated responses to detected threats. This release complements Wiz's existing agentless security coverage for Cloud Run.

## Attack Chain

1.  An attacker gains initial access to a Cloud Run container, potentially through a vulnerability in the application code or a misconfiguration in the container image.
2.  The attacker executes a malicious binary within the container that was not part of the original image.
3.  The attacker initiates a reverse shell connection from the container to an external command-and-control server, establishing a communication channel.
4.  The attacker performs reconnaissance within the container environment, enumerating sensitive data and potential lateral movement opportunities.
5.  The attacker attempts to escalate privileges within the container or the underlying Google Cloud environment by exploiting IAM permissions.
6.  The attacker performs DNS queries to known malicious domains, indicating potential command-and-control or data exfiltration activity.
7.  Wiz Runtime Sensor detects the suspicious activities, correlates the detections into a consolidated threat, and triggers automated response policies.
8.  Automated responses, such as terminating the malicious process or blocking specific runtime behaviors, are enacted to contain the threat.

## Impact

Successful attacks on Google Cloud Run containers can lead to unauthorized access to sensitive data, disruption of services, and potential compromise of the underlying Google Cloud environment. If cryptomining is performed, this could trigger multiple detections, including a file associated with a known cryptominer, a DNS query to a known mining pool, a cryptominer command line argument, and reverse shell activity. The damage can range from data breaches and financial losses to reputational damage and legal liabilities.

## Recommendation

*   Deploy the Wiz Runtime Sensor on Google Cloud Run to gain real-time visibility into container execution and enable threat detection and response.
*   Utilize the 2000+ built-in threat detection rules provided by the Wiz Runtime Sensor, and extend the detection library with custom rules tailored to your environment.
*   Enable automated response policies within Wiz to automatically terminate malicious processes, block specific runtime behaviors, or trigger workflows in response to detected threats.
*   Investigate suspicious events flagged by the Wiz Runtime Sensor by using the Wiz Blue Agent for forensics and code analysis.
*   Monitor DNS queries to block known malicious domains observed via Wiz detections, as detailed in the IOC table.
*   Enable Sysmon process creation logging to enhance visibility of process execution inside containers and trigger detections.
