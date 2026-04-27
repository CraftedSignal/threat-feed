---
title: OpenClaw Improper Trust Boundary Vulnerability (CVE-2026-41295)
slug: 2026-04-openclaw-trust-boundary
description: OpenClaw before 2026.4.2 contains an improper trust boundary vulnerability (CVE-2026-41295) allowing attackers to execute unintended code by cloning a workspace with a malicious plugin claiming a bundled channel id.
date: "2026-04-21T00:16:29Z"
severities:
  - high
tags:
  - openclaw
  - code-execution
  - trust-boundary
  - plugin
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2026-41295
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41295
  - https://github.com/openclaw/openclaw/commit/53c29df2a9eb242a70d0ff29f3d1e67c8d6801f0
  - https://github.com/openclaw/openclaw/security/advisories/GHSA-2qrv-rc5x-2g2h
  - https://www.vulncheck.com/advisories/openclaw-untrusted-workspace-channel-shadow-code-execution-during-built-in-channel-setup
rules:
  - title: OpenClaw Malicious Plugin Load
    description: Detects the loading of potentially malicious plugins in OpenClaw by monitoring process creation events related to plugin loading.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: OpenClaw Suspicious Network Connection by Plugin
    description: Detects network connections initiated by OpenClaw plugins, which could indicate command and control or data exfiltration.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

OpenClaw before version 2026.4.2 is vulnerable to an improper trust boundary issue. This vulnerability allows an attacker to achieve in-process code execution by exploiting the way OpenClaw handles workspace channel shadows. Specifically, an attacker can clone a workspace and include a malicious plugin. This plugin claims a bundled channel ID, which results in the execution of untrusted code during the built-in channel setup and login process, even before the plugin is explicitly trusted by the…
