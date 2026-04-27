---
title: Cilium `cilium-bugtool` WireGuard Private Key Exposure
slug: 2026-04-cilium-wg-key-disclosure
description: The `cilium-bugtool` debugging tool in Cilium exposes WireGuard private keys, potentially allowing unauthorized access to encrypted node-to-node communication in affected versions.
date: "2026-04-26T12:00:00Z"
severities:
  - high
tags:
  - cilium
  - wireguard
  - key-disclosure
  - credential-access
vendors:
  - Cilium
  - Isovalent
products:
  - Cilium
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1588
    technique_name: Obtain Capabilities
references:
  - https://github.com/advisories/GHSA-gj49-89wh-h4gj
ioc_counts:
  email: 1
rules:
  - title: Detect `cilium-bugtool` Execution
    description: Detects execution of the `cilium-bugtool` command, which may indicate an attempt to gather debugging information that could contain sensitive data.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - linux
  - title: Detect `cilium sysdump` Execution
    description: Detects execution of the `cilium sysdump` command, which may indicate an attempt to gather debugging information that could contain sensitive data.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A vulnerability exists in the `cilium-bugtool` utility within Cilium, an open-source networking and security platform for cloud-native environments. When used with WireGuard Transparent Encryption enabled, the tool can inadvertently include the WireGuard private key (`cilium_wg0.key`) in its output. This affects Cilium versions v1.19 between v1.19.0 and v1.19.2, v1.18 between v1.18.0 and v1.18.8, and all versions prior to v1.17.15. The exposure occurs because the tool, used for debugging and…
