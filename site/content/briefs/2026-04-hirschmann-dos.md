---
title: Hirschmann EagleSDV Denial-of-Service Vulnerability (CVE-2022-4986)
slug: 2026-04-hirschmann-dos
description: Hirschmann EagleSDV devices are vulnerable to denial-of-service (DoS) attacks where a device crash can be triggered by establishing TLS 1.0 or TLS 1.1 connections, leading to service disruption.
date: "2026-04-02T22:16:23Z"
severities:
  - high
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

Hirschmann EagleSDV devices are susceptible to a denial-of-service vulnerability, identified as CVE-2022-4986. This vulnerability allows an attacker to crash the device by establishing TLS sessions using the outdated TLS 1.0 or TLS 1.1 protocols. Successful exploitation results in service unavailability, impacting network operations reliant on the affected device. The vulnerability stems from improper handling of older TLS versions during session establishment. Given the critical role EagleSDV…
