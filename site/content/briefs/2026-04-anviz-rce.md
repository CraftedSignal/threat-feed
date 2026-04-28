---
title: Anviz CX2 Lite and CX7 Unauthenticated Remote Code Execution via Unverified Update Packages (CVE-2026-40066)
slug: 2026-04-anviz-rce
description: Anviz CX2 Lite and CX7 devices are vulnerable to unverified update packages that allow for unauthenticated remote code execution by unpacking and executing a malicious script.
date: "2026-04-17T20:16:35Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - cve-2026-40066
  - rce
  - iot
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1205
    technique_name: Traffic Signaling
cves:
  - id: CVE-2026-40066
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40066
  - https://github.com/cisagov/CSAF/blob/develop/csaf_files/OT/white/2026/icsa-26-106-03.json
  - https://www.anviz.com/contact-us.html
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-106-03
rules:
  - title: Detect Network Connection to Anviz Device for Firmware Update
    description: Detects network connections to Anviz devices attempting to download firmware updates, which could indicate exploitation of CVE-2026-40066
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1205
    data_sources:
      - network_connection
      - windows
  - title: Detect Suspicious Process Creation on Anviz Device
    description: Detects suspicious process creation on Anviz devices, such as execution of shell scripts or unusual binaries, indicating potential RCE
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The Anviz CX2 Lite and CX7 devices are susceptible to a critical vulnerability (CVE-2026-40066) stemming from the lack of integrity checks on update packages. An attacker can upload a crafted update package to the device. The vulnerable devices then unpack the contents of this package and execute a script without proper authentication or verification. This leads to unauthenticated remote code execution, potentially allowing the attacker to gain complete control over the compromised device. The vulnerability was reported by ICS-CERT and assigned a CVSS v3.1 base score of 8.8, indicating a high severity. Successful exploitation of this vulnerability allows an attacker to perform any action on the device, including stealing data, installing malware, or using the device as a foothold for further attacks on the network.

## Attack Chain

1.  Attacker identifies an Anviz CX2 Lite or CX7 device accessible on the network.
2.  Attacker crafts a malicious update package containing a script designed for remote code execution.
3.  The attacker uploads the malicious update package to the device's update interface. Due to the vulnerability, this upload may not require authentication.
4.  The device unpacks the contents of the update package, including the malicious script.
5.  The device executes the script without proper verification or sanitization.
6.  The malicious script executes arbitrary commands on the device.
7.  The attacker gains remote shell access to the device.
8.  The attacker leverages the compromised device to move laterally within the network or exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2026-40066 results in unauthenticated remote code execution on the affected Anviz CX2 Lite and CX7 devices. This can lead to complete compromise of the device, allowing attackers to steal sensitive data, install malware, or use the device as a pivot point to gain access to other systems on the network. Given the potential for widespread deployment of these devices in various sectors, the impact could be significant, affecting many organizations.

## Recommendation

*   Apply any available patches or updates from Anviz to address CVE-2026-40066.
*   Monitor network traffic for suspicious activity related to Anviz devices attempting to download or install update packages, and deploy the network connection rule below.
*   Implement network segmentation to limit the potential impact of a compromised Anviz device on other systems.
*   Monitor process creation on Anviz devices for unusual or unexpected processes, and deploy the process creation rule below.
