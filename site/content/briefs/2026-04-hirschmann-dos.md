---
title: Hirschmann EagleSDV Denial-of-Service Vulnerability (CVE-2022-4986)
slug: 2026-04-hirschmann-dos
description: Hirschmann EagleSDV devices are vulnerable to denial-of-service (DoS) attacks where a device crash can be triggered by establishing TLS 1.0 or TLS 1.1 connections, leading to service disruption.
date: "2026-04-02T22:16:23Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - denial-of-service
  - cve-2022-4986
  - network-device
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Denial of Service
cves:
  - id: CVE-2022-4986
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2022-4986
  - https://www.belden.com/security
rules:
  - title: Detect TLS 1.0 or 1.1 Connection Attempts
    description: Detects network connections attempting to use TLS 1.0 or TLS 1.1, which may indicate exploitation attempts against CVE-2022-4986.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - network_connection
      - zeek
  - title: Detect EagleSDV Device Crash
    description: Detects log entries indicating a crash of a Hirschmann EagleSDV device, potentially caused by CVE-2022-4986.
    platform: sigma
    severity: critical
    tactics:
      - availability
    techniques:
      - T1498
    data_sources:
      - device_health
      - eaglesdv
rules_count: 2
---

Hirschmann EagleSDV devices are susceptible to a denial-of-service vulnerability, identified as CVE-2022-4986. This vulnerability allows an attacker to crash the device by establishing TLS sessions using the outdated TLS 1.0 or TLS 1.1 protocols. Successful exploitation results in service unavailability, impacting network operations reliant on the affected device. The vulnerability stems from improper handling of older TLS versions during session establishment. Given the critical role EagleSDV devices play in network infrastructure, this vulnerability poses a significant risk to organizations that have not yet patched their systems or disabled the deprecated protocols.

## Attack Chain

1.  The attacker identifies a vulnerable Hirschmann EagleSDV device accessible over the network.
2.  The attacker crafts a TLS connection request using TLS 1.0.
3.  The attacker sends the crafted TLS 1.0 connection request to the target EagleSDV device.
4.  The EagleSDV device attempts to process the TLS 1.0 handshake.
5.  Due to the vulnerability, the device encounters an error during the session establishment phase of the TLS handshake.
6.  This error leads to uncontrolled resource consumption (CWE-400) within the device's TLS processing module.
7.  The resource exhaustion causes the device's operating system to become unstable.
8.  The device crashes, resulting in a denial-of-service condition.

## Impact

Successful exploitation of CVE-2022-4986 leads to a denial-of-service condition on the affected Hirschmann EagleSDV device. This can disrupt network services and cause downtime. The number of affected devices and sectors is unknown, but the impact could be significant for organizations relying on these devices for critical infrastructure.

## Recommendation

*   Disable TLS 1.0 and TLS 1.1 on all Hirschmann EagleSDV devices to mitigate the vulnerability described in CVE-2022-4986.
*   Monitor network traffic for attempts to establish TLS connections using TLS 1.0 and TLS 1.1 to identify potential exploitation attempts using a network monitoring solution (network_connection log source).
