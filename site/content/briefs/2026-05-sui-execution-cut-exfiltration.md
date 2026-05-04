---
title: Malicious sui-execution-cut Crate Exfiltrates Build Machine Data
slug: 2026-05-sui-execution-cut-exfiltration
description: The `sui-execution-cut` crate on crates.io contained a build script designed to exfiltrate data from the build machine during the build process.
date: "2026-05-04T21:42:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - malware
  - rust
products:
  - sui-execution-cut
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-qprh-m6p3-hwxc
rules:
  - title: Detect Suspicious Outbound Connections from Build Processes
    description: Detects outbound network connections from common build processes that are not typically expected.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious File System Activity from Build Processes
    description: Detects file system activity, such as listing environment variables, from build processes that are not typically expected.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - file_event
      - windows
rules_count: 2
---

On April 20, 2026, a malicious crate named `sui-execution-cut` was published to crates.io. This crate included a build script that, when executed, attempted to exfiltrate data from the machine on which the crate was being built. The crate had no dependencies and only one version was ever published. The malicious package was quickly removed from crates.io after discovery. While the crate was available for a short period, there is no evidence of actual usage, however, supply chain compromises can have a wide impact if successful, and even this low-usage crate warrants monitoring.

## Attack Chain

1. A developer adds the malicious `sui-execution-cut` crate as a dependency to their Rust project.
2. During the build process, the `cargo` build system executes the build script embedded within the `sui-execution-cut` crate.
3. The build script executes a series of commands designed to gather sensitive information from the build environment.
4. The script establishes an outbound network connection to a remote server controlled by the attacker.
5. The gathered data is transmitted to the attacker's server via HTTP POST or a similar method.
6. The attacker receives the exfiltrated data, which could include environment variables, file contents, or other sensitive information.
7. The attacker analyzes the stolen data for valuable secrets, credentials, or intellectual property.

## Impact

The `sui-execution-cut` crate, if used, could have compromised developer machines by exfiltrating sensitive data during the build process. Although the crate was quickly removed and showed no signs of usage, a successful attack of this nature could lead to the exposure of secrets, credentials, and intellectual property. The lack of usage limits the impact, but the nature of supply chain attacks makes even low-usage crates a potential risk.

## Recommendation

*   Monitor for unexpected network connections originating from build processes, especially connections to unknown or suspicious domains. Use the "Detect Suspicious Outbound Connections from Build Processes" Sigma rule.
*   Implement strict dependency review processes to identify and prevent the introduction of malicious packages into your software supply chain.
*   Continuously monitor crates.io and other package repositories for reports of malicious packages and promptly remove them from your dependencies if identified.
