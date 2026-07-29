---
title: Tool Enumeration Detected via Defend for Containers
slug: 2026-07-tool-enumeration-container
description: Elastic Defend for Containers detects the enumeration of installed tools within a Linux container using the `which` command, a common adversary technique (T1518, T1613) for post-compromise discovery and living-off-the-land actions, enabling subsequent payload download, cluster manipulation, or reconnaissance without deploying new binaries.
date: "2026-07-29T12:48:23Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - container
  - discovery
  - linux
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1518
    technique_name: Software Discovery
    evidence: This rule detects the enumeration of tools by the 'which' command inside a container. The 'which' command is used to list what tools are installed on a system, and may be used by an adversary to gain information about the container and the services running inside it.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: 'Adversaries do this to quickly assess built-in tools for living-off-the-land actions like payload download, cluster manipulation, or reconnaissance without dropping new binaries. Example: after compromising a Kubernetes pod, an operator runs which curl wget kubectl nmap python to decide how to transfer data, interact with the API, or probe the network.'
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/discovery_tool_enumeration.toml
rules:
  - title: Tool Enumeration Detected via Defend for Containers
    description: Detects the enumeration of tools by the 'which' command inside a Linux container. This activity is often performed by adversaries to gain information about the container and services running within it, informing subsequent living-off-the-land actions.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1518
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This brief describes a detection for tool enumeration within Linux containers, specifically targeting the use of the `which` command. Threat actors, upon gaining initial access to a containerized environment (e.g., a Kubernetes pod), commonly employ discovery techniques to understand their environment. The `which` command is a simple yet effective way for adversaries to identify what utilities are pre-installed and available for use in the compromised container. This activity, observed by Elastic Defend for Containers v9.3.0+, is a key indicator of post-exploitation reconnaissance. By discovering tools like `curl`, `wget`, `kubectl`, `nmap`, or `python`, attackers can plan subsequent "living-off-the-land" actions, such as downloading additional payloads, interacting with the Kubernetes API, or performing network scanning, all without introducing new malicious binaries which could trigger other defenses. While `which` can be used legitimately for debugging, its use in conjunction with suspicious processes or in specific environments warrants investigation.

## Attack Chain

1. **Initial Access**: An adversary gains unauthorized access to a Linux container, often through a compromised application or misconfigured Kubernetes deployment.
2. **Shell Access**: The adversary establishes an interactive shell session within the compromised container, potentially via `kubectl exec` or a similar mechanism.
3. **Discovery - Direct Execution**: The adversary executes the `which` command directly (e.g., `/usr/bin/which curl`) to determine if specific tools are installed and their executable paths.
4. **Discovery - Shell Execution**: Alternatively, the adversary runs a shell (e.g., `bash`, `sh`, `python`) and passes `which` as an argument to enumerate tools (e.g., `bash -c "which wget"`).
5. **Targeted Tool Enumeration**: The adversary specifically queries for the presence of networking tools (`curl`, `wget`, `socat`), container management utilities (`kubectl`, `docker`), compilation tools (`gcc`, `clang`), or scanning tools (`nmap`, `masscan`).
6. **Information Gathering**: The `which` command returns the paths to any found executables, providing the attacker with valuable information about the container's capabilities.
7. **Decision Making**: Based on the enumerated tools, the adversary decides on subsequent "living-off-the-land" actions to achieve their objectives.
8. **Post-Discovery Actions**: The attacker proceeds with actions such as downloading additional tools or payloads, manipulating the Kubernetes cluster, performing internal network reconnaissance, or exfiltrating data, using the identified legitimate binaries.

## Impact

Successful tool enumeration by an adversary provides critical intelligence about the compromised container's environment, enabling more effective and stealthy follow-on attacks. If not detected and mitigated, this discovery phase can lead to significant consequences including data exfiltration, unauthorized access to other cluster resources, privilege escalation, or full cluster compromise. For instance, if `kubectl` is discovered, an attacker could potentially manipulate Kubernetes API objects, delete pods, or deploy new, malicious containers. Similarly, finding `nmap` or `masscan` could lead to extensive internal network scanning, revealing vulnerable services. The impact can extend from a single container to the entire cloud environment, with potential for widespread service disruption, data loss, or persistent unauthorized access.

## Recommendation

* Deploy the Sigma rule "Tool Enumeration Detected via Defend for Containers" to your SIEM and tune for your environment to detect suspicious `which` command usage.
* Review the container's process tree and TTY session around alerts to determine if the `which` command was followed by the execution of enumerated utilities or other suspicious activity.
* Analyze outbound network connections and DNS queries from affected pods for unfamiliar destinations or cluster control-plane endpoints, correlating with the `network_connection` and `dns_query` log sources.
* Harden container images by adopting "distroless" or minimal base images that omit unnecessary utilities like `curl`, `wget`, `nc`, `python`, and `kubectl` to reduce living-off-the-land options.
* Implement admission controls to block interactive `kubectl exec/attach` to production pods and enforce `runAsNonRoot`, read-only root filesystems, and dropped Linux capabilities to reduce attacker impact.
