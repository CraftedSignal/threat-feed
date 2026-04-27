---
title: D-Link DIR-825 Buffer Overflow Vulnerability in miniupnpd
slug: 2024-01-dlink-dir825-buffer-overflow
description: A buffer overflow vulnerability (CVE-2026-7069) exists in the AddPortMapping function of the miniupnpd component within D-Link DIR-825 routers (up to version 3.00b32), potentially enabling attackers on the local network to execute arbitrary code.
date: "2024-01-02T12:00:00Z"
severities:
  - high
tags:
  - buffer-overflow
  - cve
  - miniupnpd
  - d-link
vendors:
  - D-Link
products:
  - DIR-825
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
cves:
  - id: CVE-2026-7069
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-7069
rules:
  - title: Detect HTTP POST Requests to UPnP Service
    description: Detects HTTP POST requests commonly used to interact with the UPnP service, potentially indicating exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
  - title: Detect Long NewPortMappingDescription in UPnP SOAP Requests
    description: Detects abnormally long NewPortMappingDescription values in UPnP SOAP requests, indicative of a potential buffer overflow attempt (CVE-2026-7069).
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A buffer overflow vulnerability, identified as CVE-2026-7069, has been discovered in D-Link DIR-825 routers with firmware versions up to 3.00b32. The vulnerability resides within the `AddPortMapping` function of the `upnpsoap.c` file, part of the `miniupnpd` component. An attacker on the local network can exploit this vulnerability by manipulating the `NewPortMappingDescription` argument, leading to a buffer overflow. Given that the exploit is publicly available, the risk of exploitation is…
