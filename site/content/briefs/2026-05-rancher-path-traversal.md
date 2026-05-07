---
title: Rancher Extensions Path Traversal Vulnerability
slug: 2026-05-rancher-path-traversal
description: A path traversal vulnerability (CVE-2026-25705) exists in Rancher's Extensions through the `compressedEndpoint` field in a `UIPlugin` deployment, allowing malicious UI extensions to overwrite Rancher binaries, tamper with cluster state, or write to the host filesystem.
date: "2026-05-07T01:25:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - rancher
  - kubernetes
vendors:
  - SUSE
products:
  - Rancher
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-5v3h-x4wf-5c35
  - https://capec.mitre.org/data/definitions/126.html
rules:
  - title: Detect Suspicious CompressedEndpoint Path Traversal
    description: Detects attempts to exploit the path traversal vulnerability in Rancher's compressedEndpoint field within UIPlugin deployments by identifying '..' sequences in the compressedEndpoint URL.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect UIPlugin CR Modification with Suspicious Path
    description: Detects attempts to create or modify UIPlugin custom resources with a suspicious path in the compressedEndpoint field, indicating potential path traversal.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A path traversal vulnerability has been identified in Rancher's Extensions, specifically affecting versions prior to v2.14.1, v2.13.5, v2.12.9, and v2.11.13. The vulnerability resides in the `compressedEndpoint` field within a `UIPlugin` deployment. A malicious actor could craft a UI extension containing a path traversal sequence, allowing them to manipulate files outside of the intended directory. This can be achieved by exploiting the installation process of UI plugins, where the `compressedEndpoint` field is not properly validated against path traversal attacks. Successfully exploiting this vulnerability could lead to arbitrary code execution within the Rancher management plane, compromising cluster infrastructure.

## Attack Chain

1. An attacker crafts a malicious UI extension containing a crafted `index.yaml` file.
2. The malicious `index.yaml` includes a `compressedEndpoint` with a path traversal sequence (e.g., `../../`).
3. An administrator (or a user with sufficient privileges) installs the malicious UI extension through the Rancher UI or API.
4. During the installation process, Rancher attempts to retrieve the compressed extension from the specified endpoint.
5. Due to the path traversal vulnerability, the attacker can write to arbitrary file system locations.
6. The attacker overwrites a Rancher binary or configuration file with malicious code.
7. The attacker could also write to `/var/lib/rancher/` to tamper with cluster state, or write to the host node filesystem if `hostPath` volumes are mounted.
8. The malicious code executes, granting the attacker control over the Rancher instance and potentially the underlying Kubernetes clusters.

## Impact

Successful exploitation of this vulnerability allows an attacker to achieve arbitrary code execution on the Rancher management plane. This could lead to a complete compromise of the Rancher instance and the connected Kubernetes clusters. An attacker could potentially gain access to sensitive information, such as cluster credentials and application data. The affected versions include Rancher versions v2.14.0, v2.13.0-v2.13.4, v2.12.0-v2.12.8, v2.10.11-v2.11.12.

## Recommendation

*   Upgrade Rancher to a patched version (v2.14.1, v2.13.5, v2.12.9, or v2.11.13) to remediate the vulnerability as described in the advisory.
*   Implement strict controls on who can deploy UI extensions, as mentioned in the overview.
*   Monitor Rancher logs for suspicious activity related to UI extension installations.
*   Deploy the Sigma rule `Detect Suspicious CompressedEndpoint Path Traversal` to detect exploitation attempts.
