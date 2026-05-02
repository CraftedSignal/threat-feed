---
title: Unusual Process Connecting to Docker or Containerd Socket
slug: 2024-01-unusual-container-socket-connection
description: An unusual process connecting to a container runtime Unix socket like Docker or Containerd can indicate an attacker attempting to bypass Kubernetes security measures for container manipulation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container
  - privilege-escalation
  - lateral-movement
  - linux
vendors:
  - Elastic
  - Docker
  - Kubernetes
products:
  - Auditbeat
  - Auditd Manager
  - Docker
  - containerd
  - kubelet
affected_os:
  - linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1613
    technique_name: Container and Resource Discovery
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
references:
  - https://attack.mitre.org/techniques/T1611/
  - https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation
rules:
  - title: Unusual Process Connecting to Docker Socket
    description: Detects processes not normally associated with container management connecting to the Docker socket.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - network_connection
      - linux
  - title: Unusual Process Connecting to Containerd Socket
    description: Detects processes not normally associated with container management connecting to the containerd socket.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - network_connection
      - linux
rules_count: 2
---

This threat involves unauthorized processes connecting directly to container runtime sockets (Docker or Containerd) on Linux systems. This bypasses Kubernetes API server restrictions, potentially allowing attackers to create, execute, or manipulate containers without proper authorization or logging. The risk lies in attackers circumventing RBAC, admission webhooks, and pod security standards. The attack can start when a compromised process attempts to connect to the Docker or Containerd socket, potentially leading to privilege escalation and lateral movement within the containerized environment. This attack is significant because it undermines core security controls within container orchestration platforms.

## Attack Chain

1. A malicious or compromised process gains initial access to the host system.
2. The process attempts to connect to the container runtime socket (e.g., `/var/run/docker.sock` or `/run/containerd/containerd.sock`).
3. The process bypasses the Kubernetes API server and associated security controls.
4. The attacker exploits the direct socket connection to create a new container.
5. The attacker gains access to sensitive data or resources within the container.
6. The attacker escalates privileges within the compromised container.
7. The attacker uses the compromised container to move laterally to other containers or hosts within the environment.
8. The attacker achieves their objective, such as data exfiltration or system compromise.

## Impact

Successful exploitation allows attackers to bypass Kubernetes security measures, create unauthorized containers, and potentially gain control over the entire cluster. The observed impact includes privilege escalation, lateral movement, and data exfiltration. The severity of this attack depends on the level of access granted to the compromised container and the sensitivity of the data and resources within the cluster.

## Recommendation

*   Enable Auditd Manager to capture network and socket events, specifically monitoring for `connect` calls to Unix sockets as described in the [Auditd Manager documentation](https://docs.elastic.co/integrations/auditd_manager).
*   Deploy the Sigma rule "Unusual Process Connecting to Docker or Containerd Socket" to detect suspicious processes connecting to container runtime sockets, tuning `process.executable` and `user.name` for known legitimate processes.
*   Monitor file permissions on the socket paths (`/var/run/docker.sock`, `/run/docker.sock`, `/var/run/containerd/containerd.sock`, `/run/containerd/containerd.sock`) and restrict access to trusted groups only.
