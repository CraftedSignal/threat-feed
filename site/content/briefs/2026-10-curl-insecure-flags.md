---
title: Detection of Insecure Curl Execution in Kubernetes Clusters
slug: 2026-10-curl-insecure-flags
description: Threat actors may leverage curl with insecure flags within Kubernetes environments to bypass TLS certificate verification, facilitating man-in-the-middle attacks and unauthorized tool ingress.
date: "2026-10-12T17:36:38Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - kubernetes
  - cloud-security
  - process-monitoring
vendors:
  - Cisco
products:
  - Isovalent Runtime Security
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: The analytic detects curl commands that use the -k or --insecure flags, which could allow an attacker to bypass SSL/TLS verification.
    confidence_band: high
references:
  - https://rawcode7.medium.com/understanding-the-kubernetes-attack-surface-9a48ebcb6bc4
  - https://www.tutorialworks.com/kubernetes-curl/
rules:
  - title: Detect Curl Execution With Insecure Flags
    description: Detects the use of curl command-line arguments that bypass SSL/TLS verification, which may indicate malicious tool ingress.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
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
    - action: Deploy Sigma rule to monitor for insecure curl flags in CI/CD and runtime environments.
      owner: Detection Engineering
      due: 48h
      evidence: Rule defined in brief.
  hunt_leads:
    - lead: Search historical logs for curl commands with -k or --insecure.
      technique_id: T1105
      data_needed:
        - Process execution telemetry
      priority: medium
      confidence: high
      disposition: hunt_now
      evidence: Source document indicates this is a known technique for bypassing TLS.
  mitigation_plan:
    - priority: medium
      action: Enforce TLS certificate validation for all outbound connections in cluster network policies.
      owner: IT Operations
      addresses: T1105
      evidence: Technique relies on bypassing certificate validation.
---

Monitoring of Kubernetes environments reveals that curl commands are frequently executed with insecure flags, such as -k or --insecure, to circumvent SSL/TLS verification during file transfers. This activity is often associated with the ingress of unauthorized tools or payloads into containerized environments. Within the Cisco Isovalent platform, defenders can monitor process execution logs to identify these commands. This behavior is notable because bypassing certificate validation exposes the infrastructure to man-in-the-middle attacks, potentially leading to sensitive data interception, service disruption, or unauthorized access to the cluster. SOC teams should investigate such executions to determine if they originate from legitimate administrative scripts or indicate malicious activity.

## Attack Chain

1. Attacker gains initial access to a Kubernetes pod, possibly via compromised container applications.
2. Attacker attempts to download external malicious tools or configuration files using curl.
3. The target server uses self-signed or invalid certificates, preventing standard curl requests.
4. Attacker executes curl with the -k or --insecure flag to force the connection despite certificate validation errors.
5. The insecure connection is established, potentially allowing an interceptor to perform a man-in-the-middle attack.
6. The attacker successfully pulls the secondary stage payload or configuration into the container.
7. The attacker executes the downloaded payload to conduct further malicious actions, such as lateral movement or data exfiltration.

## Impact

Successful exploitation allows attackers to bypass infrastructure security controls, leading to the ingress of unauthorized payloads, potential interception of sensitive communications, and unauthorized access to the Kubernetes control plane or pod secrets. This impacts security posture by weakening the transport layer security required for cloud-native workloads.

## Recommendation

* Deploy detection logic to monitor process execution logs within the Cisco Isovalent environment for curl commands containing insecure flags.
* Audit administrative scripts and container entrypoints that utilize curl to ensure certificate verification is enforced where feasible.
* Use the provided Sigma rule to detect these command-line arguments in process monitoring telemetry.
* Investigate triggered alerts by cross-referencing with pod activity and established cron jobs to reduce noise from legitimate administrative tasks.
