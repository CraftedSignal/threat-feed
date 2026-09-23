---
title: KubeEdge keadm Arbitrary File Write via Path Traversal
slug: 2026-09-kubeedge-path-traversal
description: KubeEdge keadm utility contains a path traversal vulnerability (CVE-2026-62369) in its archive extraction function, allowing an attacker to overwrite arbitrary files on Windows systems during edge node join or installation.
date: "2026-09-23T01:55:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:kubeedge:kubeedge:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - file-write
  - path-traversal
  - windows
vendors:
  - KubeEdge
products:
  - keadm (>= 1.16.0, < 1.21.2)
  - keadm (>= 1.22.0, < 1.22.2)
  - keadm (>= 1.23.0, < 1.23.1)
affected_os:
  - Windows
cves:
  - id: CVE-2026-62369
    cvss: 8.1
references:
  - https://github.com/advisories/GHSA-9vm9-pqxx-x83v
  - https://nvd.nist.gov/vuln/detail/CVE-2026-62369
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade KubeEdge keadm to v1.21.2, 1.22.2, or 1.23.1
      owner: IT Operations
      due: 48h
      evidence: Source specifies these versions contain the fix for CVE-2026-62369
  mitigation_plan:
    - priority: immediate
      action: Restrict account privileges for keadm execution and enforce verification of archive source integrity
      owner: Security Engineering
      addresses: CVE-2026-62369
      evidence: Workaround provided in GHSA-9vm9-pqxx-x83v
---

KubeEdge `keadm` contains a path traversal vulnerability in its `DecompressTarGz` function, which is utilized during the edge node join and installation process. The vulnerability stems from the direct joining of archive entry names with the target destination path without sufficient validation. An attacker capable of providing a malicious `.tar.gz` archive can leverage path traversal components, Windows-style backslashes, absolute paths, or drive-prefixed paths to write or overwrite files outside the intended destination directory.

This vulnerability (CVE-2026-62369) specifically impacts Windows environments where `keadm` extracts component archives. Depending on the privileges of the user executing the `keadm` command, an attacker can modify critical system files, including configuration files, executables, or service-related artifacts. Successful exploitation could lead to persistent system modification or unauthorized code execution. Mitigation requires upgrading to KubeEdge v1.21.2, v1.22.2, or v1.23.1, or ensuring that only trusted KubeEdge component archives are used during installation.

## Impact

The vulnerability allows an attacker to bypass directory constraints during archive extraction on Windows hosts. Depending on the targeted file, this can result in privilege escalation, system persistence, or full compromise of the affected edge node. This is particularly critical for administrative users or service accounts running `keadm` with high-privilege context on Windows edge infrastructure.

## Recommendation

* Upgrade KubeEdge to versions 1.21.2, 1.22.2, or 1.23.1 or later to implement secure file path validation in `DecompressTarGz`.
* Enforce strict supply chain controls by only utilizing official and verified KubeEdge package sources.
* Restrict write permissions and administrative privileges for the service account or user executing the `keadm` join process.
* Implement integrity verification for all downloaded archives prior to triggering the `keadm` extraction routines.
