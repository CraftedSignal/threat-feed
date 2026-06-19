---
title: Arbitrary Host File Read via Symlink Following in containerd CRI Checkpoint Restore (CVE-2026-53489)
slug: 2026-06-containerd-symlink-read
description: A high-severity vulnerability (CVE-2026-53489) in containerd's CRI plugin allows an unprivileged attacker to read arbitrary files on the host system by crafting a malicious checkpoint with a symlink that `containerd` follows during `container.log` restoration, enabling data exfiltration via `kubectl logs`.
date: "2026-06-19T19:44:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - container
  - kubernetes
  - vulnerability
  - data-exfiltration
  - linux
vendors:
  - containerd
products:
  - containerd v2.1.0-2.1.8
  - containerd v2.2.0-2.2.4
  - containerd v2.3.0-2.3.1
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
references:
  - https://github.com/advisories/GHSA-rgh6-rfwx-v388
rules:
  - title: Detects CVE-2026-53489 Exploitation — containerd Reading Sensitive System Files (Shadow)
    description: Detects CVE-2026-53489 exploitation where containerd reads the /etc/shadow file, indicating potential symlink traversal from a malicious container log. This is an indicator of arbitrary host file disclosure.
    platform: sigma
    severity: high
    tactics:
      - collection
      - discovery
    techniques:
      - T1005
      - T1083
    data_sources:
      - file_event
      - linux
  - title: Detects CVE-2026-53489 Exploitation — containerd Reading Sensitive System Files (Passwd)
    description: Detects CVE-2026-53489 exploitation where containerd reads the /etc/passwd file, indicating potential symlink traversal from a malicious container log. This is an indicator of arbitrary host file disclosure.
    platform: sigma
    severity: high
    tactics:
      - collection
      - discovery
    techniques:
      - T1005
      - T1083
    data_sources:
      - file_event
      - linux
  - title: Detects CVE-2026-53489 Exploitation — containerd Accessing SSH Private Keys
    description: Detects CVE-2026-53489 exploitation where containerd attempts to read files commonly associated with SSH private keys from the host filesystem, indicating an attempt to exfiltrate credentials via symlink traversal.
    platform: sigma
    severity: critical
    tactics:
      - collection
      - credential_access
    techniques:
      - T1005
      - T1552.004
    data_sources:
      - file_event
      - linux
rules_count: 3
---

A critical bug, tracked as CVE-2026-53489, has been identified in the containerd CRI plugin, impacting versions prior to 2.3.2, 2.2.5, and 2.1.9. This vulnerability allows an attacker to achieve arbitrary host file disclosure. The flaw stems from `containerd` failing to validate symlinked paths when restoring `container.log` from a checkpoint image. By crafting a malicious checkpoint that includes `container.log` as a symbolic link to a sensitive host file, an attacker can leverage a standard `kubectl logs` command to retrieve the contents of that file. This poses a significant risk of data exfiltration and unauthorized information gathering from the underlying host system, impacting Kubernetes and other container orchestration environments. The vulnerability was independently discovered by multiple researchers, indicating a high likelihood of exploitation potential.

## Attack Chain

1.  **Craft Malicious Checkpoint/Image**: An attacker creates a container image or checkpoint where the expected `container.log` file is replaced with a symbolic link pointing to a sensitive file on the host filesystem (e.g., `/etc/shadow`, `/root/.ssh/id_rsa`).
2.  **Deploy Malicious Image**: The attacker deploys this specially crafted container image to a Kubernetes cluster or container environment running a vulnerable version of containerd.
3.  **Containerd Restores Checkpoint**: When the container is started or its checkpoint is restored, the `containerd` CRI plugin attempts to initialize the `container.log` path.
4.  **Symlink Traversal**: Due to the vulnerability (CVE-2026-53489), `containerd` follows the malicious symlink instead of validating the path, effectively linking the container's `container.log` output stream to the sensitive host file.
5.  **Attacker Requests Logs**: The attacker, possessing appropriate permissions to view container logs (e.g., via `kubectl logs`), issues a command to retrieve the logs of the compromised container.
6.  **Containerd Reads Target File**: `containerd`, processing the log request, reads the content of the file pointed to by the symlink (the sensitive host file).
7.  **Data Exfiltration**: The content of the sensitive host file is then returned to the attacker as if it were legitimate container log output, achieving arbitrary host file disclosure.

## Impact

The successful exploitation of CVE-2026-53489 can lead to significant information disclosure. Attackers can read any file accessible by the `containerd` process on the host system. This could include sensitive configuration files (e.g., `/etc/kubernetes/kubelet.conf`), SSH keys, credentials, or other proprietary data stored on the host. While the vulnerability doesn't directly grant remote code execution, the ability to read arbitrary files can be a crucial step in further privilege escalation or data exfiltration attacks within a compromised Kubernetes cluster or container host. All organizations running containerd versions prior to the patched releases are at risk, particularly those that allow deployment of untrusted container images.

## Recommendation

*   **Patch CVE-2026-53489**: Immediately update containerd to patched versions (2.3.2, 2.2.5, or 2.1.9) as described in the GHSA advisory.
*   **Implement Image Trust**: Ensure that only trusted container images and checkpoints are used within your environment to minimize the risk of malicious artifacts.
*   **Deploy File Access Monitoring**: Configure host-level file activity monitoring (e.g., Auditd, Falco) to detect suspicious `containerd` process access to sensitive files or directories. Deploy the Sigma rules provided in this brief.
*   **Enable Sysmon for Linux**: For Linux hosts, consider enabling Sysmon for Linux to capture `FileCreate` and `FileRead` events which can be used by the Sigma rules below.
