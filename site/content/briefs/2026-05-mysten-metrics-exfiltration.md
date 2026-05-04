---
title: Malicious mysten-metrics Crate Exfiltrates Build Machine Data
slug: 2026-05-mysten-metrics-exfiltration
description: The `mysten-metrics` crate was removed from crates.io after it was found to contain a malicious build script that attempted to exfiltrate data from the build machine during the build process.
date: "2026-05-04T21:43:56Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - malware
  - rust
vendors:
  - MystenLabs
products:
  - mysten-metrics
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
references:
  - https://github.com/advisories/GHSA-g38r-8gmr-ghrf
rules:
  - title: Detect Network Connections from Build Scripts
    description: Detects network connections initiated by rust build scripts which may indicate malicious activity.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - linux
  - title: Detect Suspicious File Access During Build Process
    description: Detects access to sensitive files by cargo during build processes.
    platform: sigma
    severity: high
    tactics:
      - discovery
    techniques:
      - T1005
    data_sources:
      - file_event
      - linux
rules_count: 2
---

On April 20, 2026, a malicious crate named `mysten-metrics` was published to crates.io. This crate contained a build script designed to exfiltrate data from the machine during the build process. The crate was identified and removed from crates.io. At the time of removal, only one version of the crate had been published, and there was no evidence of actual usage. The crate had no dependencies on crates.io, limiting the potential spread. This incident highlights the risks associated with supply chain attacks targeting software build processes and the importance of verifying the integrity of third-party dependencies.

## Attack Chain

1.  Attacker publishes the `mysten-metrics` crate to crates.io.
2.  A developer adds `mysten-metrics` as a dependency to their project.
3.  The developer builds the project using `cargo build`.
4.  As part of the build process, the malicious build script within `mysten-metrics` is executed.
5.  The build script collects sensitive data from the build environment (e.g., environment variables, file contents, system information).
6.  The build script attempts to exfiltrate the collected data to a remote attacker-controlled server. The exact exfiltration method is not specified, but could involve HTTP/S requests or DNS tunneling.
7.  The attacker receives the exfiltrated data from the compromised build machine.

## Impact

The successful execution of the malicious build script could lead to the exposure of sensitive information, including API keys, credentials, source code, and other confidential data present on the build machine. This data could be used to compromise the developer's infrastructure, intellectual property, and customer data. Since there were no known usages, the impact was contained by its early removal.

## Recommendation

*   Implement integrity checks for all third-party dependencies to identify and prevent the use of malicious packages.
*   Monitor network connections originating from build processes for suspicious outbound traffic, as this could indicate data exfiltration. Create network connection rules.
*   Implement file integrity monitoring on build machines to detect unauthorized modifications to files during the build process.
