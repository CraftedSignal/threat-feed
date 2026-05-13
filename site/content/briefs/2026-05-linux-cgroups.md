---
title: Leveraging Linux Cgroups for Threat Detection and Investigation
slug: 2026-05-linux-cgroups
description: This brief outlines how Linux cgroups, a kernel feature for resource management, can be repurposed to provide valuable telemetry for detecting malicious processes, particularly in systemd, Docker, and Kubernetes environments, aiding in investigations of server compromises.
date: "2026-05-13T13:03:36Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - linux
  - cgroups
  - container
  - kubernetes
  - docker
  - systemd
  - threat-detection
vendors:
  - Red Hat
  - Canonical
  - Docker
  - Google
products:
  - Red Hat Enterprise Linux
  - Ubuntu
  - Debian
  - Arch Linux
  - Docker runtime
  - Kubernetes
affected_os:
  - Linux
references:
  - https://redcanary.com/blog/threat-detection/linux-cgroups/
rules:
  - title: Detect Unexpected Processes in Docker Container (via Cgroup)
    description: Detects processes running inside a Docker container but not originating from a standard container runtime path, indicating potential malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect User-Level Systemd Service Execution (via Cgroup)
    description: Detects processes running under user-level systemd services, potentially indicating unauthorized service creation or hijacking.
    platform: sigma
    severity: low
    tactics:
      - persistence
    techniques:
      - T1543.002
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Linux cgroups (control groups) are a kernel feature designed for resource management, allowing administrators to limit the resources available to specific processes. While intended for system stability and performance, cgroups also expose valuable telemetry that can be leveraged for threat detection and incident response. This is particularly useful in modern Linux environments heavily reliant on containerization and systemd. Defenders can utilize cgroup information to gain deeper insights into process behavior, establish relationships between processes, and differentiate between benign and malicious activities. By understanding how cgroups are structured and utilized by different systems, security teams can enhance their ability to detect and respond to threats on Linux servers. The blog post highlights the practical application of cgroups in systemd, Docker, and Kubernetes environments, providing a foundation for building more effective detection strategies.

## Attack Chain

1.  Attacker gains initial access to a Linux server, potentially through exploiting a vulnerability or using compromised credentials.
2.  Attacker executes a malicious script or binary on the server.
3.  The malicious process is assigned a cgroup by the system, depending on whether it's managed by systemd, Docker, or Kubernetes.
4.  If the process is a systemd service, it will be associated with a cgroup under `/system.slice/`, which reveals the service name.
5.  If the process is running within a Docker container, it will be assigned a cgroup under `/docker/$CONTAINER_ID`, allowing for grouping of all container processes.
6.  In a Kubernetes environment, the cgroup path will include the pod ID and Quality-of-Service class, such as `/kubepods/$CLASS/pod$POD_ID/$CONTAINER_ID` (cgroupfs driver) or `/kubepods.slice/kubepods-$CLASS.slice/$POD_ID.slice/$CONTAINER_ID` (systemd driver).
7.  The attacker attempts lateral movement or persistence, spawning additional processes that inherit the same cgroup, which can be used to correlate attacker activity.
8.  The attacker achieves their objective, such as deploying a coinminer or exfiltrating sensitive data, leaving behind processes that can be identified and grouped via their cgroup assignment.

## Impact

Compromised Linux servers can lead to data breaches, service disruptions, and resource hijacking. If an attacker successfully establishes persistence, they can maintain unauthorized access for extended periods. The presence of coinminers can degrade system performance and increase energy consumption. Understanding the cgroup assignments of malicious processes can aid in identifying the scope of the compromise, the attacker's objectives, and the affected systems.

## Recommendation

*   Monitor process creation events and collect the associated cgroup path to establish baselines of normal system behavior, especially within containerized environments.
*   Deploy the provided Sigma rule to detect unexpected processes running within Docker containers based on the cgroup path.
*   Use the provided Sigma rule to detect processes running under user-level systemd services, correlating with user login sessions to identify anomalous behavior.
*   Investigate processes with unusual cgroup assignments, particularly those lacking expected container or systemd associations.
*   Correlate cgroup information with other telemetry, such as network connections and file modifications, to gain a more comprehensive understanding of attacker activity.
*   Utilize the `systemd-cgls` command on Linux systems to list all active cgroups and their associated processes for manual investigation and validation of detection rules.
