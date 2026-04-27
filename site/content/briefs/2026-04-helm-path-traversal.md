---
title: Helm Plugin Path Traversal Vulnerability
slug: 2026-04-helm-path-traversal
description: A path traversal vulnerability in Helm versions 4.0.0 to 4.1.3 allows a malicious plugin to write files to arbitrary locations on the filesystem, leading to potential system compromise.
date: "2026-04-11T12:00:00Z"
severities:
  - high
tags:
  - helm
  - path-traversal
  - vulnerability
  - plugin
  - kubernetes
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1566
    technique_name: Impair System
cves:
  - id: CVE-2026-35204
    epss: 0.00013
references:
  - https://github.com/advisories/GHSA-vmx8-mqv2-9gmg
rules:
  - title: Helm Plugin Install with Path Traversal
    description: Detects Helm plugin installations where the plugin.yaml contains path traversal sequences in the version field.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1566
    data_sources:
      - file_event
      - linux
  - title: Suspicious Helm Plugin Update with Path Traversal
    description: Detects Helm plugin updates where the plugin.yaml contains path traversal sequences in the version field.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1566
    data_sources:
      - file_event
      - linux
rules_count: 2
---

Helm, a package manager for Kubernetes charts, is vulnerable to a path traversal issue. Specifically, Helm versions 4.0.0 through 4.1.3 are affected. A maliciously crafted Helm plugin, when installed or updated, can exploit this vulnerability (CVE-2026-35204) to write the plugin's contents to arbitrary locations on the user's filesystem. This can lead to overwriting critical system files or user data, potentially compromising the system's integrity. Helm v4.1.4 resolves this vulnerability by…
