---
title: Linux Container Escape via Kernel core_pattern Modification
slug: 2026-07-container-escape-core-pattern
description: Attackers can exploit a Linux kernel vulnerability allowing a process inside a container to modify the `/proc/sys/kernel/core_pattern` file, enabling the execution of arbitrary code as root on the host system upon a core-dump, thereby achieving a full container-to-host escape and privilege escalation.
date: "2026-07-03T15:17:46Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container-escape
  - privilege-escalation
  - linux
  - kubernetes
  - endpoint
products:
  - Linux kernel
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: A process inside a container that can write core_pattern can register an attacker-controlled handler and then deliberately crash a process to have it execute on the host as root, resulting in a full container-to-host escape.
    confidence_band: high
references:
  - https://www.sysdig.com/blog/runc-container-escape-vulnerabilities
  - https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm
  - https://kubehound.io/reference/attacks/CE_UMH_CORE_PATTERN/
  - https://aquasecurity.github.io/tracee/latest/docs/events/builtin/signatures/core_pattern_modification/
rules:
  - title: Potential Container Escape via Kernel core_pattern Modification
    description: Detects suspicious modifications of the Linux kernel's core_pattern parameter, which can be leveraged for container-to-host escape and privilege escalation.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1611
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

This threat describes a critical container escape and privilege escalation vulnerability within the Linux kernel, enabling attackers to gain root access on the host system from a compromised container. The vulnerability leverages the non-namespaced nature of the kernel's core-dump handler mechanism. A malicious process running within a container can write to the `/proc/sys/kernel/core_pattern` file, a kernel interface that specifies how core-dumps are handled. If the value written to this file begins with a pipe symbol ('|'), the kernel executes the remainder of the string as a command, running it from the host's initial namespace with root privileges, regardless of the crashing process's origin. This provides a direct vector for a containerized attacker to execute arbitrary commands on the underlying host, circumventing container isolation.

## Attack Chain

1.  An attacker gains initial access to a Linux container, typically through a vulnerable application or misconfiguration.
2.  Within the compromised container, the attacker identifies their ability to modify kernel parameters, specifically the `/proc/sys/kernel/core_pattern` file.
3.  The attacker creates or locates a malicious script on the container's filesystem that, if executed on the host, would grant them persistent root access or other objectives.
4.  The attacker modifies `/proc/sys/kernel/core_pattern` within the container, setting its value to `|/path/to/malicious_script` (or similar), directing the kernel to execute their script upon a core-dump.
5.  The attacker then deliberately triggers a core-dump from any process inside the container.
6.  The Linux kernel, upon detecting the core-dump, invokes the `core_pattern` handler. Due to the vulnerability, it executes `/path/to/malicious_script` from the host's initial namespace as root.
7.  The malicious script executes with root privileges on the host, allowing the attacker to achieve full host compromise and maintain persistence outside the container.

## Impact

Successful exploitation of this vulnerability leads to a full container-to-host escape and privilege escalation. An attacker initially confined to a container gains root-level access to the underlying host system. This can result in complete control over the host, enabling data exfiltration, deployment of additional malware (e.g., ransomware, cryptominers), installation of backdoors, and disruption of other services or containers running on the same host. The impact is severe, as it undermines the fundamental security isolation provided by containerization technologies.

## Recommendation

*   Deploy the Sigma rule "Potential Container Escape via Kernel core_pattern Modification" to detect attempts to modify the `core_pattern` from within containers.
*   Ensure that container runtime security policies restrict modification of `/proc/sys/kernel/core_pattern` or prevent execution of `sysctl -w` commands that alter kernel parameters, particularly from untrusted containerized applications.
*   Implement strong ingress and egress filtering for containers to prevent outbound communication to attacker-controlled infrastructure post-escape.
*   Regularly scan containers and host systems for vulnerabilities and misconfigurations that could allow initial container compromise.
