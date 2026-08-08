---
title: Remote Command Injection in D-Link DWR-M961
slug: 2026-08-dlink-command-injection
description: D-Link DWR-M961 devices with hardware version C1 and firmware versions prior to 1.1.5_C1_202607071108 are vulnerable to unauthenticated command injection via the fota_url parameter.
date: "2026-08-08T17:40:26Z"
lastmod: "2026-08-08T17:40:45Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - remote-code-execution
  - network-security
vendors:
  - D-Link
products:
  - DWR-M961
  - DWR-M961 (< 1.1.5_C1_202607071108)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A remote attacker can inject arbitrary malicious commands into the fota_url field, resulting in command execution with root privileges.
    confidence_band: high
cves:
  - id: CVE-2026-71944
    cvss: 9.8
  - id: CVE-2026-71945
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71944
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71945
rules:
  - title: Detects CVE-2026-71944 Exploitation - Potential Command Injection in D-Link DWR-M961
    description: Detects potential command injection attempts targeting the FOTA upgrade interface of D-Link DWR-M961 devices by monitoring for shell metacharacters in the fota_url parameter.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
updates:
  - at: "2026-08-08T17:40:45Z"
    level: L2
    summary: added CVE-2026-71945; dwr-m961 version < 1.1.5_C1_202607071108
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71945
---

D-Link DWR-M961 routers, specifically hardware version C1, contain a critical command injection vulnerability identified as CVE-2026-71944. The vulnerability exists within the firmware upgrade interface located at /boafrm/formLtefotaUpgradeQuectel. An unauthenticated remote attacker can exploit this flaw by sending a crafted HTTP request containing malicious commands in the fota_url parameter. Successful exploitation allows the attacker to execute arbitrary code with root privileges on the affected device, potentially leading to a complete compromise of the router. This vulnerability highlights the risks associated with improper input validation in router administrative interfaces. Defenders should prioritize patching, as this device class is a common target for botnet recruitment and persistent unauthorized access.

## Impact

The vulnerability carries a CVSS 3.1 base score of 9.8, indicating high severity and ease of exploitation. An attacker who successfully triggers this vulnerability gains full administrative control over the DWR-M961 device. Potential impacts include device bricking, participation in DDoS botnets, man-in-the-middle attacks on local network traffic, and establishment of persistent backdoors within the organization's network perimeter.

## Recommendation

Prioritize updating the firmware of all D-Link DWR-M961 (C1 hardware) devices to version 1.1.5_C1_202607071108 or later immediately. Ensure these devices are not exposed to the public internet by placing them behind a firewall or using a VPN for remote management.
