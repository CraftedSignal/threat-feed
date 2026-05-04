---
title: Kata Containers CopyFile Policy Subversion via Symlinks
slug: 2024-01-03-kata-containers-copyfile-symlink
description: An oversight in the CopyFile policy in Kata Containers allows untrusted hosts to write to arbitrary locations inside the guest workload image via symlinks, enabling binary overwrites and data exfiltration.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kata-containers
  - container-escape
  - symlink
vendors:
  - kata-containers
products:
  - kata-containers/kata-containers (< 0.0.0-20260422180503-1b9e49eb2763)
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-41326
    epss: 0.00019
references:
  - https://github.com/advisories/GHSA-q49m-57vm-c8cc
rules:
  - title: Detect Symlink Creation in Kata Containers Shared Directory
    description: Detects the creation of symbolic links within the Kata Containers shared directory, which could indicate an attempt to exploit the CopyFile vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - persistence
      - privilege_escalation
    techniques:
      - T1547.004
    data_sources:
      - file_event
      - linux
  - title: Detect Kata Containers CopyFile Request with Suspicious Path
    description: Detects CopyFile requests with a suspicious file path, potentially indicating directory traversal or attempts to write outside the intended target directory.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Modification of Executable Files via CopyFile
    description: Detects modification of common executable files using CopyFile API.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - file_event
      - linux
rules_count: 3
---

An oversight in the CopyFile policy within Kata Containers allows a malicious host to manipulate guest workload images. The vulnerability stems from insufficient validation within the `CopyFileRequest` policy, specifically related to symlink creation. The policy primarily checks the destination path of copied files but fails to adequately validate the target of symlinks created via the same API. This flaw was discovered by @calonso-nv and impacts environments where the `genpolicy` implementation is used to prevent host access to container images, including Confidential Containers workloads which rely on strong isolation. If the guest image is not protected from the host (e.g., when using unprotected host pull), the system is not vulnerable. The affected package is `go/github.com/kata-containers/kata-containers` versions prior to `0.0.0-20260422180503-1b9e49eb2763`.

## Attack Chain

1. The attacker identifies a target file within the guest container image, such as a binary or configuration file they wish to overwrite.
2. The attacker crafts a `CopyFileRequest` to create a symbolic link within the `/run/kata-containers/shared/containers` directory.
3. The `path` parameter of the request specifies the location of the symlink within the shared directory.
4. The `data` parameter of the request specifies the target of the symbolic link, which points to the target file identified in step 1, inside the guest file system.
5. The Kata Agent processes the `CopyFileRequest`, creating the symbolic link within the shared directory, pointing to the target file inside the container image.
6. The attacker crafts a second `CopyFileRequest` to copy malicious data into the symlink created in step 5.
7. The Kata Agent writes the malicious data to the symlink, which then overwrites the original target file within the container image.
8. The attacker restarts the container or waits for the compromised binary to be executed, achieving arbitrary code execution within the guest.

## Impact

Successful exploitation allows attackers to overwrite arbitrary files within container images managed by Kata Containers. This can lead to arbitrary code execution within the guest environment, data exfiltration, and privilege escalation. This is particularly critical in Confidential Containers environments where the trust model explicitly forbids host access to container images. Affected systems are those employing the upstream `genpolicy` implementation.

## Recommendation

*   Apply the patch or upgrade to `go/github.com/kata-containers/kata-containers` version `0.0.0-20260422180503-1b9e49eb2763` or later to address CVE-2026-41326.
*   Monitor the creation of symbolic links within the `/run/kata-containers/shared/containers` directory, using the provided Sigma rule, as this is an unusual operation (file_event).
*   Implement strict access controls and monitoring for the Kata Agent to prevent unauthorized `CopyFileRequest` messages.
