---
title: Detection of AWS Credential Exfiltration via Linux Curl
slug: 2026-10-linux-curl-aws-exfil
description: The TeamTNT threat group leverages the curl utility to exfiltrate sensitive AWS credential and configuration files to remote attacker-controlled servers.
date: "2026-10-12T17:50:13Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - TeamTNT
tags:
  - exfiltration
  - linux
  - aws
  - living-off-the-land
products:
  - AWS (credentials/config files)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This activity is significant as it may indicate an attempt to exfiltrate sensitive AWS credentials, a technique known to be used by the TeamTNT group.
    confidence_band: high
rules:
  - title: Detect Linux Curl AWS Credential Upload
    description: Detects the use of curl with upload switches targeting .aws/credentials or .aws/config files, a technique associated with TeamTNT.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1105
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
    - action: Deploy Sigma rule to monitor for curl-based credential exfiltration
      owner: Detection Engineering
      due: 48h
      evidence: Source detection documentation
  hunt_leads:
    - lead: Identify all processes named 'curl' with command line arguments containing '.aws/credentials'
      technique_id: T1105
      data_needed:
        - Process command line telemetry
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source detection logic
---

Security research indicates that the threat group known as TeamTNT actively exploits legitimate Linux binaries to exfiltrate sensitive cloud configuration data. Specifically, attackers use the curl utility to upload AWS credentials (~/.aws/credentials) and configuration files (~/.aws/config) to remote destinations. This technique relies on curl's form-based or direct file upload switches, such as -F, --upload-file, or -T. By exfiltrating these files, the actor gains unauthorized access to the victim's AWS environment, potentially leading to resource theft, crypto-mining deployment, or further network lateral movement. Defenders should monitor process command-line arguments for the combination of curl upload flags and sensitive path references.

## Attack Chain

1. Attacker gains initial shell access to a Linux-based cloud instance or container.
2. Attacker performs local reconnaissance to locate cloud credentials, typically in ~/.aws/credentials or ~/.aws/config.
3. Attacker identifies the availability of the curl binary on the compromised system.
4. Attacker constructs a malicious curl command utilizing upload switches (-F, --form, -T, or --upload-file) targeting the identified credential files.
5. Attacker executes the curl command, directing the POST request to an attacker-controlled remote endpoint.
6. Exfiltrated credentials are received by the attacker's server, enabling cloud resource hijacking.

## Impact

Successful exfiltration allows for the full compromise of the victim's AWS environment. This exposes the organization to data theft, unauthorized API access, and the deployment of compute-intensive workloads such as cryptominers, which can lead to significant financial costs and infrastructure instability.

## Recommendation

* Deploy the provided Sigma rule to detect curl executions involving sensitive AWS file paths.
* Enable comprehensive Sysmon for Linux (Event ID 1) or equivalent EDR process-creation telemetry to ensure visibility into command-line arguments.
* Configure alerting for all outbound curl traffic to non-authorized domains from cloud-resident Linux hosts.
