---
title: Container-to-Host Escape via Kernel core_pattern Modification
slug: 2026-07-container-escape-core-pattern
description: Attackers can achieve container-to-host escape and privilege escalation on Linux systems by manipulating the `kernel.core_pattern` setting within a container, causing the host to execute an attacker-controlled script as root when a process core-dumps.
date: "2026-07-06T14:31:31Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - container-escape
  - linux-privesc
  - privilege-escalation
  - container
  - kubernetes
  - linux
  - threat-detection
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1611
    technique_name: Escape to Host
    evidence: The Linux kernel invokes the program named in '/proc/sys/kernel/core_pattern' whenever a process core-dumps. When that value begins with a pipe (|), the kernel runs the handler from the host's initial namespace as root, regardless of where the crashing process lived.
    confidence_band: high
references:
  - https://www.sysdig.com/blog/runc-container-escape-vulnerabilities
  - https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm
  - https://kubehound.io/reference/attacks/CE_UMH_CORE_PATTERN/
  - https://aquasecurity.github.io/tracee/latest/docs/events/builtin/signatures/core_pattern_modification/
rules:
  - title: Potential Container Escape via Kernel core_pattern Modification
    description: Detects attempts to modify the Linux kernel's core_pattern parameter, which attackers can leverage for container-to-host escape by executing arbitrary code on the host as root.
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

This threat involves a known container escape technique on Linux systems that leverages the `kernel.core_pattern` kernel parameter. Attackers who have gained initial access to a container can exploit this mechanism to achieve full host compromise and privilege escalation. The technique involves modifying the `core_pattern` value, typically found in `/proc/sys/kernel/core_pattern`, to point to an attacker-controlled script or binary, prefixed with a pipe (`|`) character. When a process inside the container is then deliberately crashed, the Linux kernel invokes the specified handler from the host's initial namespace as root, effectively bypassing container isolation. This allows an attacker to execute arbitrary commands on the underlying host system with elevated privileges, posing a significant risk to the integrity and confidentiality of the host and other workloads. The technique has been widely documented and applies to various container runtimes.

## Attack Chain

1.  Attacker gains initial access and code execution within a container running on a Linux host.
2.  Attacker identifies the ability to modify the `/proc/sys/kernel/core_pattern` file, often requiring specific container capabilities or privileged execution.
3.  Attacker writes a malicious script (e.g., to `/tmp`) and then modifies `/proc/sys/kernel/core_pattern` to `|/tmp/malicious_script` using commands like `echo`, `sysctl -w`, `tee`, `cp`, or `mv`.
4.  Attacker deliberately crashes a process within the compromised container (e.g., using `kill -SEGV <pid>`).
5.  The Linux kernel's core-dump handler is triggered by the crashing process and invokes the path specified in `kernel.core_pattern`.
6.  The `malicious_script` is executed from the host's initial namespace with root privileges, bypassing container boundaries.
7.  Attacker establishes persistence or further compromises the host system, achieving full container-to-host escape.

## Impact

Successful exploitation of this technique results in a complete bypass of container isolation, leading to full compromise of the underlying host system. This grants the attacker root-level privileges on the host, allowing them to access sensitive data, install persistence mechanisms, deploy additional malware (e.g., cryptocurrency miners, ransomware, backdoors), pivot to other systems in the environment, or manipulate other containers. The impact can extend to data exfiltration, service disruption, and significant financial and reputational damage. While no specific victim counts are provided, any organization utilizing Linux containers is potentially vulnerable if container security best practices are not rigidly enforced.

## Recommendation

*   Deploy the Sigma rule in this brief to your SIEM and tune for your environment to detect suspicious modifications to `kernel.core_pattern`.
*   Ensure endpoint security solutions like Elastic Defend are properly configured and deployed to collect process creation and kernel parameter modification events on all Linux hosts running containers.
*   Monitor `/proc/sys/kernel/core_pattern` for changes, particularly those that introduce pipe-based handlers (`|`) or reference untrusted paths.
*   Harden container environments by preventing privileged pods, removing dangerous capabilities such as `CAP_SYS_ADMIN`, and prohibiting writable `hostPath` access to `/proc` or the host filesystem.
*   Implement admission policies to enforce pod security standards and prevent workloads from running with excessive privileges that would allow modification of host kernel parameters.
