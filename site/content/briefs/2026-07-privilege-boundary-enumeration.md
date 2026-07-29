---
title: Privilege Boundary Enumeration in Linux Containers
slug: 2026-07-privilege-boundary-enumeration
description: This brief details the detection of commands such as 'id', 'whoami', 'capsh', 'getcap', and 'lsns' executed within Linux containers by adversaries seeking to enumerate privilege boundaries, user context, and Linux capabilities for privilege escalation or host escape, as detected by Elastic Defend for Containers.
date: "2026-07-29T12:44:51Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - container-security
  - linux
  - discovery
  - cloud
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
    evidence: These commands are used to enumerate the privilege boundary of the container, which can be used by an adversary to gain information about the container and the services running inside it.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: System Information Discovery
    evidence: These commands are used to enumerate the privilege boundary of the container, which can be used by an adversary to gain information about the container and the services running inside it.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
    evidence: These commands are used to enumerate the privilege boundary of the container, which can be used by an adversary to gain information about the container and the services running inside it.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/cloud_defend/discovery_privilege_boundary_enumeration_from_interactive_process.toml
rules:
  - title: Detect Privilege Boundary Enumeration in Linux Containers
    description: Detects the execution of 'id', 'whoami', 'capsh', 'getcap', or 'lsns' commands inside a Linux container, which are used by attackers to enumerate the container's privilege boundaries.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1033
      - T1082
      - T1613
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This threat brief focuses on the detection of specific Linux commands used by attackers within containerized environments. Adversaries frequently employ utilities like `id`, `whoami`, `capsh`, `getcap`, and `lsns` early in an intrusion to map the privilege boundaries, user context, and Linux capabilities of a compromised container. This information is crucial for attackers to determine potential avenues for privilege escalation within the container or to pivot towards a host escape. The detection, implemented by Elastic Defend for Containers, signals suspicious discovery activity that suggests an attacker has gained initial access and is now surveying the environment. This technique is often observed after an attacker successfully compromises a container via a vulnerable service and obtains a shell, using these commands to assess the environment before attempting further exploitation.

## Attack Chain

1. **Initial Access**: An attacker gains a remote shell or executes arbitrary code within a Linux container, often by exploiting a vulnerable service (e.g., a web application) exposed by the container.
2. **Container Context Discovery**: Upon gaining access, the attacker immediately executes commands like `id` and `whoami` to ascertain the current user and group context within the container.
3. **Privilege Boundary Enumeration**: The attacker then uses tools such as `capsh`, `getcap`, and `lsns` to discover the specific Linux capabilities granted to the container process and to understand its namespace isolation, looking for weaknesses.
4. **Internal Privilege Escalation**: Based on the enumerated privileges and configuration, the attacker attempts to escalate privileges within the container itself.
5. **Host Escape/Lateral Movement**: If successful in escalating privileges or identifying a vulnerability, the attacker exploits container configuration (e.g., privileged mode, hostPath mounts, host namespace sharing) to escape the container to the underlying host or move to other containers.
6. **Achieve Objective**: The attacker completes their mission, which could include data exfiltration, resource hijacking, or establishing persistence on the host system.

## Impact

Successful privilege boundary enumeration, if followed by exploitation, can lead to severe consequences, including full compromise of the affected container, the underlying host system, and potentially other services in the cluster. This can result in unauthorized access to sensitive data, disruption of services, resource hijacking for illicit activities (e.g., cryptocurrency mining), or serving as a pivot point for broader network compromise. While the discovery stage itself might seem low impact, it is a critical precursor to more damaging actions. The true impact depends on the container's privileges and access to host resources; a privileged container with host mounts can be used for full system takeover.

## Recommendation

* Deploy the provided Sigma rule to your SIEM and tune for your environment to detect suspicious privilege boundary enumeration.
* Review Kubernetes audit logs or container runtime events for the workload generating an alert to determine the origin of the interactive session.
* Ensure logging for process creation events is enabled for your Linux container environments to support the Sigma rule.
* Implement admission controls and policy (e.g., Pod Security Admission, Gatekeeper, Kyverno) to enforce least-privilege security contexts for containers, such as running as non-root, dropping unnecessary capabilities, and preventing host mounts/sockets.
* Disable or tightly restrict interactive `exec`/`attach` functionality for production container workloads to limit initial access for attackers.
