---
title: KubeVirt virt-exportserver Path Traversal Vulnerability (CVE-2026-9804)
slug: 2026-05-kube-virt-path-traversal
description: A path traversal vulnerability exists in KubeVirt's virt-exportserver component, where an attacker with namespace-level access can exploit this flaw by creating a symbolic link within an exported filesystem PVC to read arbitrary files from the exporter pod, leading to information disclosure.
date: "2026-05-28T09:19:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - kube-virt
  - path-traversal
  - vulnerability
  - cloud
vendors:
  - KubeVirt
products:
  - virt-exportserver
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1552
    technique_name: Unsecured Credentials
cves:
  - id: CVE-2026-9804
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9804
rules:
  - title: Detect CVE-2026-9804 Exploitation Attempt via Symlink Creation
    description: Detects CVE-2026-9804 exploitation attempt by detecting symlink creation events in exported PVC directories by a non-root user
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1552.004
    data_sources:
      - file_event
      - linux
  - title: Detect CVE-2026-9804 Exploitation Attempt via File Access
    description: Detects CVE-2026-9804 exploitation attempt by detecting file access from virt-exportserver outside the PVC mount
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1552.004
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A path traversal vulnerability, identified as CVE-2026-9804, has been discovered in the virt-exportserver component of KubeVirt. This flaw allows an attacker with specific namespace-level access to exploit the VMExport directory endpoint. By crafting a malicious symbolic link within an exported filesystem Persistent Volume Claim (PVC), the attacker can point outside of the designated mount root of the PVC. This circumvents access controls and permits reading arbitrary files from the exporter pod's filesystem. Successful exploitation results in information disclosure, potentially exposing sensitive data residing on the KubeVirt host. This vulnerability impacts systems where KubeVirt's virt-exportserver is deployed and accessible to potentially malicious actors with the requisite namespace permissions.

## Attack Chain

1.  Attacker gains namespace-level access to the KubeVirt environment.
2.  Attacker identifies a VMExport configured with an exported filesystem PVC.
3.  Attacker creates a symbolic link within the exported filesystem PVC. The symbolic link is crafted to point outside the PVC's designated mount root, targeting sensitive files on the exporter pod's filesystem.
4.  The attacker triggers the export process, causing the virt-exportserver to follow the symbolic link.
5.  Due to the path traversal vulnerability, the virt-exportserver reads the file pointed to by the symbolic link, which resides outside the intended PVC scope.
6.  The virt-exportserver includes the content of the targeted file in the export stream.
7.  The attacker retrieves the export stream, gaining access to the contents of the previously inaccessible file.
8.  The attacker successfully exfiltrates sensitive information from the KubeVirt environment.

## Impact

Successful exploitation of CVE-2026-9804 allows an attacker with namespace-level access to read arbitrary files from the exporter pod's filesystem. This information disclosure could expose sensitive data, such as configuration files, credentials, or other confidential information stored on the KubeVirt host. The vulnerability could lead to a compromise of the KubeVirt environment, enabling further malicious activities. The number of affected systems depends on the deployment size of KubeVirt.

## Recommendation

*   Deploy the Sigma rule `Detect CVE-2026-9804 Exploitation Attempt via Symlink Creation` to detect the creation of suspicious symbolic links within exported PVC directories, which are indicative of path traversal attempts.
*   Implement strict access control policies to limit namespace-level permissions, reducing the attack surface as described in the overview.
*   Regularly audit and monitor KubeVirt deployments for suspicious activity, focusing on file system access within PVC mounts.
*   Deploy the Sigma rule `Detect CVE-2026-9804 Exploitation Attempt via File Access` to detect file access from virt-exportserver outside the PVC mount.
