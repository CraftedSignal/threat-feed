---
title: Detection of Privileged Container Creation with Host Directory Mount
slug: 2026-09-privileged-container-host-mount
description: Attackers exploit misconfigured privileged containers using host bind-mounts to escape container isolation and gain unauthorized control over the underlying host.
date: "2026-09-18T19:16:11Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - container-escape
  - privilege-escalation
  - execution
products:
  - Docker
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1609
    technique_name: Container Administration Command
    evidence: An attacker on a compromised node starts a privileged container via the runtime.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: Such configurations can be exploited by attackers to escape the container isolation and gain access to the host system.
    confidence_band: high
rules:
  - title: Detect Privileged Container Creation with Host Mount
    description: Detects the creation of privileged Docker containers that mount the host root directory, a common technique for container escape.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1609
      - T1611
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
    - action: Review current container deployment logs for usage of the --privileged flag.
      owner: SOC
      due: 24h
      evidence: Source document identifies --privileged as the primary indicator.
  mitigation_plan:
    - priority: immediate
      action: Implement Admission Controller policies to restrict privileged container creation.
      owner: IT Operations
      addresses: T1611
      evidence: Response and remediation section recommends Pod Security Standards and OPA Gatekeeper.
---

This threat involves the exploitation of misconfigured container environments where privileged containers are deployed with host filesystems mounted directly into the container's namespace. By utilizing the --privileged flag alongside a bind-mount of the host root directory (e.g., -v /:/host), an attacker can effectively bypass container isolation mechanisms. Once inside such a container, the attacker gains direct read and write access to sensitive host files, devices, and configuration paths. This access is frequently leveraged to perform container escapes, often through chrooting into the host root or manipulating namespaces via nsenter. These techniques allow the attacker to alter critical system files, install persistence mechanisms, and pivot into the broader infrastructure, representing a significant risk to the integrity and security of the containerized node.

## Attack Chain

1. An attacker identifies a compromised node with access to the container runtime (e.g., Docker socket).
2. The attacker executes a container deployment command using the --privileged flag to disable standard security profiles.
3. The attacker adds a bind-mount argument, specifically mounting the host root filesystem (e.g., -v /:/host) into the container.
4. Upon container startup, the attacker gains shell access within the privileged environment (T1609/T1610).
5. The attacker performs a chroot command to set the root directory to the mounted host filesystem path.
6. The attacker interacts with sensitive host configuration files such as /etc/shadow, /etc/sudoers, or /root/.ssh.
7. The attacker modifies systemd units or installs SSH keys to establish long-term persistence on the host.
8. The attacker initiates a lateral movement or exfiltration phase from the compromised host (T1611).

## Impact

Successful exploitation allows for a full container escape, resulting in complete compromise of the underlying host operating system. This facilitates privilege escalation, the theft of sensitive data, the deployment of persistent backdoors, and the potential compromise of the entire container cluster if the host is a Kubernetes node.

## Recommendation

1. Deploy the provided Sigma rule to monitor for suspicious process execution patterns related to privileged container creation.
2. Implement Admission Control policies (e.g., OPA Gatekeeper or Kyverno) to deny the use of --privileged containers and hostPath mounts of the host root.
3. Enable File Integrity Monitoring (FIM) on critical host paths, specifically /etc, /root/.ssh, and /var/lib/kubelet to detect unauthorized modifications.
4. Ensure Docker/CRI sockets are restricted to authorized users and groups only.
5. Conduct audits of existing container configurations to identify and remediate instances where --privileged mode or broad hostPath mounts are in use.
