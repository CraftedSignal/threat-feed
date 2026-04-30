---
title: UniFi Play Improper Access Control Allows SSH Enablement
slug: 2026-04-unifi-play-ssh-enable
description: CVE-2026-22564 is an improper access control vulnerability in UniFi Play PowerAmp and Audio Port devices that allows an attacker with network access to enable SSH and make unauthorized system changes.
date: "2026-04-13T22:16:28Z"
severities:
  - critical
type: advisory
types:
  - advisory
tags:
  - cve-2026-22564
  - unifi-play
  - access-control
  - ssh
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-22564
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-22564
  - https://community.ui.com/releases/Security-Advisory-Bulletin-063/e468dd4b-5090-4ef8-89d8-939903c08e83
iocs:
  - type: email
    value: '[email protected]'
ioc_counts:
  email: 1
rules:
  - title: Detect SSH Login to UniFi Play Devices
    description: Detects successful SSH login events to UniFi Play devices, potentially indicating exploitation of CVE-2026-22564.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078
    data_sources:
      - network_connection
      - linux
  - title: Detect Unauthorized Process Creation on UniFi Play via SSH
    description: Detects unusual process creation on UniFi Play devices following a potential SSH compromise.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CVE-2026-22564 is a critical vulnerability affecting UniFi Play PowerAmp (version 1.0.35 and earlier) and UniFi Play Audio Port (version 1.0.24 and earlier) devices. This improper access control flaw allows a malicious actor, who has already gained access to the UniFi Play network, to enable SSH access on the affected devices. This unauthorized SSH access can then be leveraged to make arbitrary changes to the system configuration, potentially leading to full device compromise and further network exploitation. Successful exploitation requires network access to the UniFi Play devices. The vulnerability was reported by HackerOne and affects devices that have not been updated to the patched versions (PowerAmp 1.0.38 or Audio Port 1.1.9).

## Attack Chain

1. The attacker gains initial access to the UniFi Play network through unspecified means (e.g., compromised credentials, network misconfiguration, or physical access).
2. The attacker identifies vulnerable UniFi Play PowerAmp or Audio Port devices on the network running versions 1.0.35 or earlier (PowerAmp) and 1.0.24 or earlier (Audio Port).
3. The attacker exploits the improper access control vulnerability (CVE-2026-22564) by sending a crafted request to the vulnerable device.
4. This request bypasses access controls, enabling SSH access on the device.
5. The attacker uses an SSH client (e.g., OpenSSH) to connect to the device using the enabled SSH service, likely with default or easily guessable credentials (not specified in source, but common).
6. Once authenticated, the attacker executes privileged commands via the SSH shell.
7. The attacker modifies system configurations, installs malicious software, or exfiltrates sensitive data.
8. The attacker maintains persistent access to the compromised device and potentially uses it as a pivot point for further attacks within the network.

## Impact

Successful exploitation of CVE-2026-22564 allows an attacker to gain unauthorized SSH access and make arbitrary changes to vulnerable UniFi Play devices. This can result in complete device compromise, allowing for data theft, installation of malware, and disruption of services. The vulnerability has a CVSS v3.1 score of 9.8 (Critical), indicating a high potential for severe impact. The scope of impact depends on the network configuration and the data handled by the compromised UniFi Play devices.

## Recommendation

*   Immediately update UniFi Play PowerAmp devices to version 1.0.38 or later and UniFi Play Audio Port devices to version 1.1.9 or later to patch CVE-2026-22564.
*   Monitor network traffic for suspicious SSH connections to UniFi Play devices, especially from unexpected sources. Implement the provided Sigma rule targeting SSH login events.
*   Conduct a thorough review of the UniFi Play network to identify and remediate any potential initial access vectors that could be exploited to reach the vulnerable devices.
*   Review and harden default credentials on all network devices, including UniFi Play devices, to prevent attackers from easily gaining access after enabling SSH.
