---
title: Detecting Interactive File Downloads in Linux Containers via Curl and Wget
slug: 2026-07-container-file-download
description: This threat brief details how adversaries download files from the internet into Linux containers using `curl` or `wget` to stage tools, payloads, or establish application-layer command and control (C2), which detection engineers can identify by monitoring process execution within containers and correlating with audit logs.
date: "2026-07-29T12:29:51Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container-security
  - cloud-security
  - linux
  - command-and-control
  - execution
  - elastic-defend
  - threat-detection
vendors:
  - Kubernetes
  - Docker
products:
  - Kubernetes
  - Docker
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
    evidence: This rule flags activity inside a Linux container where curl or wget is used to pull content from a URL or IP and immediately write a new file, signaling hands-on retrieval of tools, payloads, or data.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This rule flags activity inside a Linux container where curl or wget is used to pull content from a URL or IP... A common pattern is an operator execing into a running container, fetching a script or binary... then saving it for rapid follow-on execution.
    confidence_band: high
references:
  - https://heilancoos.github.io/research/2025/12/16/kubernetes.html#kubelet-api
  - https://www.cyberark.com/resources/threat-research-blog/using-kubelet-client-to-attack-the-kubernetes-cluster
  - https://www.aquasec.com/blog/kubernetes-exposed-exploiting-the-kubelet-api/
rules:
  - title: Detect Interactive File Download in Linux Containers
    description: Detects the download of files from the internet into Linux containers using 'curl' or 'wget' with output flags, indicating potential staging of tools, payloads, or C2.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - execution
    techniques:
      - T1059
      - T1059.004
      - T1071
      - T1071.001
      - T1105
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This brief focuses on the detection of malicious file downloads occurring within Linux containers, a technique commonly employed by adversaries to introduce tools, secondary payloads, or establish covert command-and-control (C2) channels. Attackers often gain initial access to a container, then leverage common command-line utilities like `curl` or `wget` to retrieve external content from the internet. This method allows them to avoid embedding artifacts directly into container images, enabling a more dynamic and less detectable staging process. The Elastic Defend for Containers integration, available from version 9.3.0, specifically targets this behavior by monitoring `process_creation` events for `curl` and `wget` commands that are configured to write output to a file. Defenders must understand this technique to prevent the compromise of sensitive data, persistent C2 communication, and subsequent stages of attack within containerized environments.

## Attack Chain

1. **Initial Access to Container:** An adversary gains unauthorized access to a running Linux container, potentially through a vulnerable application, exposed API, or compromised credentials.
2. **Establish Interactive Session:** The attacker initiates an interactive shell session within the compromised container using `kubectl exec`, `docker exec`, or similar commands.
3. **Command Execution - Tool Download:** The attacker executes `curl` or `wget` within the interactive session to download a malicious file (e.g., a script, binary, or configuration file) from an internet-based URL or IP address.
4. **File Staging:** The downloaded file is immediately saved to the container's filesystem, using arguments like `-o`, `--output`, or `--output-document`.
5. **Preparation for Execution:** The attacker may then modify file permissions (e.g., `chmod +x`) to make the downloaded file executable, if it's a binary or script.
6. **Follow-on Execution:** The downloaded file is executed, potentially leading to further compromise such as establishing C2 communication, data exfiltration, privilege escalation, or lateral movement within the cluster.
7. **Impact:** The execution of the downloaded payload achieves the adversary's objective, ranging from sensitive data access to full control over the container and potentially the host system or broader Kubernetes cluster.

## Impact

The successful execution of interactive file downloads within containers can lead to significant compromise. Adversaries can gain unauthorized access to sensitive data stored within the container or accessible from it. This technique is often a precursor to establishing persistent command-and-control (C2) communication channels, allowing attackers to maintain remote control over compromised containerized workloads. The downloaded files may contain malware, custom tools, or secondary payloads designed for further exploitation, data exfiltration, or lateral movement within the victim's cloud environment or Kubernetes cluster. This can ultimately lead to business disruption, data breaches, and regulatory non-compliance.

## Recommendation

* Deploy the Sigma rule "Detect Interactive File Download in Linux Containers" to your SIEM and tune for your environment by identifying legitimate uses of `curl` and `wget` for file downloads within containers.
* Ensure that process creation logs from your containerized Linux environments, specifically those indicating `container.id` and process arguments, are collected and ingested into your security monitoring platform to enable the rule.
* Investigate alerts generated by this rule by correlating container execution events with Kubernetes audit logs or Docker daemon logs to identify the user, source IP, and access path that initiated the interactive session.
* Analyze the downloaded file's full path, size, hash, and format; retrieve it for static analysis and malware scanning.
* Restrict interactive `exec` and `attach` permissions for non-administrative roles within your container orchestration platform (e.g., Kubernetes) to limit unauthorized access.
* Implement runtime policies that block or restrict `curl` and `wget` usage within containers, especially for writing files from external sources, and enforce egress filtering to only allow outbound traffic to approved destinations.
