---
title: containerd CRI Checkpoint Restore CDI Annotation Smuggling Vulnerability (CVE-2026-53492)
slug: 2026-06-containerd-cdi-smuggling
description: A high-severity vulnerability (CVE-2026-53492) in containerd's CRI implementation allows an attacker with pod creation permissions to smuggle arbitrary Container Device Interface (CDI) annotations during container restoration, bypassing Kubernetes resource allocation and enabling unauthorized device and host mount injection into the restored container.
date: "2026-06-19T19:43:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - containerd
  - kubernetes
  - vulnerability
  - privilege-escalation
  - linux
  - cloud
vendors:
  - containerd
products:
  - containerd (< 2.1.9)
  - containerd (< 2.2.5)
  - containerd (< 2.3.2)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
references:
  - https://github.com/advisories/GHSA-33vj-92qq-66hc
  - CVE-2026-53492
rules:
  - title: Detects CVE-2026-53492 Exploitation - Container Process Accessing Sensitive Host Devices
    description: Detects processes executing within containers (spawned by containerd-shim or runc) that attempt to access sensitive raw host devices or partitions. This indicates potential privilege escalation or container escape via smuggled CDI annotations after CVE-2026-53492 exploitation.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - privilege_escalation
    techniques:
      - T1068
      - T1562
    data_sources:
      - process_creation
      - linux
  - title: Detects CVE-2026-53492 Exploitation - Container Process Accessing Host CDI Configuration
    description: Detects processes running inside containers (spawned by containerd-shim or runc) attempting to read or modify CDI configuration directories on the host, such as /etc/cdi or /var/run/cdi. This could indicate post-exploitation reconnaissance or manipulation after CVE-2026-53492 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - discovery
      - privilege_escalation
    techniques:
      - T1068
      - T1083
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A critical vulnerability, tracked as CVE-2026-53492, has been identified in the Container Runtime Interface (CRI) implementation of containerd versions prior to 2.1.9, 2.2.5, and 2.3.2. This flaw enables a user with legitimate Kubernetes pod creation permissions to bypass standard resource allocation and device plugin enforcement during the restoration of a container from a checkpoint. By crafting a malicious checkpoint image that includes forged Container Device Interface (CDI) annotations, an attacker can inject arbitrary device nodes or host mounts into the restored container. This can lead to privilege escalation within the compromised container, potentially allowing access to sensitive host resources. Successful exploitation requires CDI to be enabled on the target node and for matching host CDI specifications to be present.

## Attack Chain

1.  **Initial Access**: An attacker gains "pod creation permissions" within a Kubernetes cluster that utilizes a vulnerable version of containerd.
2.  **Malicious Checkpoint Creation**: The attacker crafts a container checkpoint archive containing metadata with forged or unauthorized Container Device Interface (CDI) annotations. These annotations specify arbitrary host device nodes or host file system paths for mounting.
3.  **Checkpoint Restoration Request**: The attacker initiates the restoration of a container from this maliciously crafted checkpoint archive via the Kubernetes API, which subsequently interacts with containerd's CRI.
4.  **Annotation Smuggling**: The vulnerable containerd CRI implementation improperly trusts and processes the CDI annotations embedded within the untrusted checkpoint image metadata, rather than strictly adhering to the pod's original create-time specification.
5.  **Unauthorized Resource Injection**: containerd proceeds to create the new container instance, incorporating the smuggled CDI annotations, which results in unauthorized host device nodes or file system paths being mounted directly into the container.
6.  **Privilege Escalation / Host Access**: The restored container gains unapproved access to sensitive host resources (e.g., raw disk devices, critical system directories), effectively bypassing Kubernetes security policies and device plugin controls.
7.  **Exploitation of Host Resources**: The attacker can then utilize this elevated access from within the container to further compromise the host, exfiltrate data, or establish persistence.

## Impact

Successful exploitation of CVE-2026-53492 allows an attacker to achieve privilege escalation within a container, gaining unauthorized access to the host's device nodes and file system. This bypasses critical Kubernetes security mechanisms, including resource allocation policies and device plugin enforcement. The vulnerability can lead to container escape, enabling the attacker to read, modify, or exfiltrate sensitive data from the host, or to gain further control over the underlying node. The impact is significant in environments where CDI is enabled and sensitive host CDI specifications exist, potentially leading to full system compromise if critical devices or paths are exposed.

## Recommendation

*   **Patch CVE-2026-53492**: Immediately update containerd to a patched version (2.3.2, 2.2.5, or 2.1.9) to mitigate CVE-2026-53492.
*   **Recreate Containers**: After patching, recreate any existing containers that were restored from untrusted checkpoints to ensure removal of any smuggled configurations.
*   **Restrict Untrusted Checkpoints**: Implement strict policies to restrict the restoration of containers from untrusted checkpoint images.
*   **CDI Workaround**: If Container Device Interface (CDI) capabilities are not actively utilized, relocate or remove host CDI specifications from the default directories (`/etc/cdi` and `/var/run/cdi`) as a temporary mitigation.
*   **Deploy Detection Rules**: Deploy the provided Sigma rules to your SIEM to detect post-exploitation activity related to CVE-2026-53492.
