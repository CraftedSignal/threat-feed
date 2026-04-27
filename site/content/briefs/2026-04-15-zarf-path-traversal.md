---
title: Zarf Path Traversal Vulnerability via Malicious Package Metadata.Name
slug: 2026-04-15-zarf-path-traversal
description: Zarf is vulnerable to path traversal due to insufficient sanitization of the Metadata.Name field in package manifests when using the `zarf package inspect sbom` or `zarf package inspect documentation` commands, potentially leading to arbitrary file write.
date: "2026-04-15T12:00:00Z"
severities:
  - high
tags:
  - zarf
  - path-traversal
  - arbitrary-file-write
  - package-inspection
  - linux
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
references:
  - https://github.com/advisories/GHSA-pj97-4p9w-gx3q
rules:
  - title: Detect Zarf Package Inspection with Path Traversal
    description: Detects zarf package inspect commands with Metadata.Name containing path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Zarf Arbitrary File Write
    description: Detects file writes by zarf to sensitive directories, indicating potential exploitation.
    platform: sigma
    severity: critical
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - linux
  - title: Detect Zarf Usage
    description: Detects execution of the zarf binary, which may indicate legitimate usage or the start of malicious activity.
    platform: sigma
    severity: informational
    tactics:
      - discovery
    data_sources:
      - process_creation
      - linux
rules_count: 3
---

Zarf, a tool for air-gapped deployments, is susceptible to a path traversal vulnerability (CVE-2026-40090) affecting versions prior to v0.74.2. The vulnerability stems from inadequate sanitization of the `Metadata.Name` field within Zarf package manifests. When a user employs the `zarf package inspect sbom` or `zarf package inspect documentation` commands on an untrusted package, the tool constructs output file paths by concatenating a user-controlled output directory with the package's…
