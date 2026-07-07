---
title: Interactive File Download in Linux Containers via Curl/Wget Detected
slug: 2026-07-container-file-download-detection
description: An Elastic Defend for Containers rule detects interactive sessions within Linux containers where `curl` or `wget` are used to download files from the internet, indicating potential adversary command and control or execution activity as threat actors often use such methods to stage payloads, tools, or data for subsequent malicious actions within compromised containerized environments.
date: "2026-07-03T15:48:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container
  - linux
  - command-and-control
  - execution
  - cloud
  - file-download
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071
    technique_name: Application Layer Protocol
    evidence: Adversaries may use these tools to download files from the internet to gain access to sensitive data or communicate with C2 servers.
    confidence_band: high
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: This rule flags an interactive session inside a Linux container that runs curl or wget to pull content from a URL or IP and immediately writes a new file, signaling hands-on retrieval of tools, payloads, or data.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: A common pattern is an operator execing into a running container, fetching a script or binary from paste/CDN infrastructure, then saving it for rapid follow-on execution.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/command_and_control_interactive_file_download_from_internet.toml
  - https://heilancoos.github.io/research/2025/12/16/kubernetes.html#kubelet-api
  - https://www.cyberark.com/resources/threat-research-blog/using-kubelet-client-to-attack-the-kubernetes-cluster
  - https://www.aquasec.com/blog/kubernetes-exposed-exploiting-the-kubelet-api/
rules:
  - title: Detect Interactive Container File Download via Curl or Wget
    description: Detects interactive sessions within Linux containers that execute curl or wget with options to save output, indicating potential ingress tool transfer or C2 communication.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
      - ingress_tool_transfer
    techniques:
      - T1059.004
      - T1071.001
      - T1105
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This threat brief details a detection rule from Elastic aimed at identifying malicious file downloads within Linux containers. The rule, released on February 6, 2026, and updated on June 30, 2026, focuses on interactive sessions where `curl` or `wget` command-line tools are used to retrieve files from external sources. Threat actors frequently leverage these tools for ingress tool transfer (MITRE ATT&CK T1105), allowing them to stage additional payloads, tools, or data for subsequent execution and establishing application-layer command and control without embedding artifacts directly into container images. This behavior is crucial for defenders to monitor as it often signals a compromised container, unauthorized access, or preparation for further malicious activity, such as exfiltration or lateral movement within the Kubernetes cluster.

## Impact

If this activity goes undetected, attackers can download and execute arbitrary code, tools, or malware within a compromised container, potentially leading to unauthorized access to sensitive data, establishing persistent command and control channels, or facilitating lateral movement across the containerized environment and underlying infrastructure. The execution of such downloaded payloads could result in data exfiltration, system compromise, resource abuse, or further stages of a multi-pronged attack. The lack of specific victim counts or targeted sectors in the source indicates a general threat applicable to any organization utilizing Linux containers.

## Recommendation

*   Deploy the Sigma rule provided in this brief to your SIEM and tune for your environment to detect `curl` or `wget` file downloads in containers.
*   Attribute the interactive session to an initiator by correlating container `exec`/`attach` events with Kubernetes audit logs or Docker daemon logs to identify the user, source IP, and access path.
*   Inspect the created file’s full path, size, format, and hash, then retrieve it from the container or node filesystem for static analysis and malware scanning.
*   Pivot on the download destination (domain/IP/URL path) to review outbound connection telemetry, DNS/TLS indicators, and threat reputation, blocking suspicious endpoints at the egress.
*   Review subsequent container activity after the download for follow-on actions such as `chmod`, interpreter execution, new processes, cron modifications, credential access, or lateral movement attempts.
*   Harden your environment by removing `exec`/`attach` permissions from non-admin roles and enforcing runtime policies that block interactive `curl`/`wget` and restrict outbound traffic to approved destinations.
