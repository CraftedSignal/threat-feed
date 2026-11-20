---
brief_id: brief-2024-01-03-log4j-java-outbound
event_id: brief-2024-01-03-log4j-java-outbound
revision: 1
activity_at: "2024-01-03T18:22:33Z"
title: Log4j Exploitation Attempt via Java Outbound Connections
slug: 2024-01-log4j-java-outbound
description: This analytic detects potential Log4j (CVE-2021-44228) exploitation attempts through outbound network connections from Java processes to default LDAP and RMI ports, indicative of malicious JNDI lookups for remote code execution.
date: "2024-01-03T18:22:33Z"
lastmod: "2026-11-20T03:10:25Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2021-11-03T00:00:00Z"
  confidence: high
cpes:
  - cpe:2.3:a:fortinet:fortiproxy:*:*:*:*:*:*:*:*
  - cpe:2.3:a:geoserver:geoserver:*:*:*:*:*:*:*:*
  - cpe:2.3:a:geotools:geotools:*:*:*:*:*:*:*:*
  - cpe:2.3:a:geotools:geotools:30.0:-:*:*:*:*:*:*
  - cpe:2.3:a:geotools:geotools:30.0:rc:*:*:*:*:*:*
  - cpe:2.3:a:geotools:geotools:31.0:-:*:*:*:*:*:*
  - cpe:2.3:a:geotools:geotools:31.0:rc:*:*:*:*:*:*
  - cpe:2.3:a:igniterealtime:openfire:*:*:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2013:cumulative_update_21:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2013:cumulative_update_22:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2013:cumulative_update_23:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_10:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_11:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_12:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_13:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_14:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_15:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_16:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_17:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_18:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_19:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_8:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2016:cumulative_update_9:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2019:-:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_1:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_2:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_3:*:*:*:*:*:*
  - cpe:2.3:a:microsoft:exchange_server:2019:cumulative_update_4:*:*:*:*:*:*
  - cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2026g2-iu\/sl_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2046g2-iu\/sl_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2066g2-i\(u\)_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2066g2-iu\/sl_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2086g2-i\(u\)_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2086g2-iu\/sl_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2166g2-i\(su\)_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2186g2-i\(su\)_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2186g2-isu_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2326g2-isu\/sl_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2346g2-isu\/sl_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2366g2-i\(u\)_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2366g2-isu\/sl_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2386g2-i\(u\)_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2386g2-isu\/sl_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2426g2-i_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2446g2-i_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2526g2-i\(s\)_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2526g2-is_firmware:-:*:*:*:*:*:*:*
  - cpe:2.3:o:hikvision:ds-2cd2546g2-i\(s\)_firmware:-:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=98D35B1B-73F9-569D-92E3-59A413C1572A&utm_source=rss&utm_medium=rss
tags:
  - log4j
  - cve-2021-44228
  - java
  - jndi
  - rmi
  - ldap
vendors:
  - Apache
  - Cisco
  - F5
  - Fortinet
  - GeoServer
  - Hikvision
  - HiSilicon
  - Ignite Realtime
  - Microsoft
  - Zimbra
products:
  - Apache Shiro
  - BIG-IP
  - Exchange Server
  - FortiOS
  - GeoServer
  - Hi3516/Hi3518/Hi3519-based DVR/NVR devices
  - Hikvision Products
  - IOS XE Web UI
  - Openfire
  - React Server Components
  - SharePoint
  - Zimbra Collaboration Suite
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1133
    technique_name: External Remote Services
cves:
  - id: CVE-2021-26855
    cvss: 9.1
    epss: 0.99999
    kev: true
    kev_status: "true"
  - id: CVE-2023-32315
    cvss: 8.6
    epss: 0.99998
    kev: true
    kev_status: "true"
  - id: CVE-2024-36401
    cvss: 9.8
    epss: 0.99813
    kev: true
    kev_status: "true"
  - id: CVE-2021-36260
    cvss: 9.8
    epss: 0.99869
    kev: true
    kev_status: "true"
  - id: CVE-2024-21762
    cvss: 9.8
    epss: 0.80835
    kev: true
    kev_status: "true"
  - id: CVE-2021-44228
    kev_status: unknown
  - id: CVE-2020-25078
    kev_status: unknown
references:
  - https://www.lunasec.io/docs/blog/log4j-zero-day/
  - https://www.govcert.admin.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/
  - https://sploitus.com/exploit?id=98D35B1B-73F9-569D-92E3-59A413C1572A&utm_source=rss&utm_medium=rss
  - https://securelist.com/strikeshark-campaign/120326/
rules:
  - title: Detect Java Outbound Connections to LDAP/RMI Ports
    description: Detects outbound network connections from Java processes to default ports used by LDAP and RMI protocols, indicating potential Log4j exploitation.
    platform: sigma
    severity: high
    tactics:
      - cve-2021-44228
      - initial_access
      - vulnerability
    techniques:
      - T1133
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Java Process Creation for Log4j Exploitation
    description: Detects the execution of Java processes that might be exploited due to the Log4j vulnerability, useful for correlation with network events.
    platform: sigma
    severity: low
    tactics:
      - cve-2021-44228
      - initial_access
      - vulnerability
    techniques:
      - T1133
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
updates:
  - at: "2026-05-26T14:19:37Z"
    level: L2
    summary: poc_available; added CVE-2020-25078 +1
    sources:
      - sploitus
  - at: "2026-06-24T10:02:47Z"
    level: L2
    summary: added CVE-2021-26855 +4; OS windows
    sources:
      - securelist
  - at: "2026-11-20T03:10:25Z"
    level: L3
    summary: exploited:true; KEV CVE-2021-26855; KEV CVE-2023-32315; KEV CVE-2024-36401; KEV CVE-2021-36260; KEV CVE-2024-21762
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

This brief focuses on detecting attempts to exploit the Log4j vulnerability (CVE-2021-44228) by monitoring outbound network connections from Java processes. The exploitation involves using specially crafted requests that force Java applications to make outbound connections to malicious LDAP or RMI servers. These requests trigger JNDI lookups, potentially downloading and executing arbitrary code. This activity is detected by monitoring process execution and network traffic, specifically outbound connections from "java.exe" or "javaw.exe" to ports 389, 636, 1099, and 1389. Defenders should prioritize monitoring systems where Java applications are running, particularly those exposed to external inputs.

## Attack Chain

1.  The attacker sends a malicious request containing a JNDI lookup string to a vulnerable application.
2.  The Log4j library parses the malicious string and initiates a JNDI lookup.
3.  The vulnerable Java process (java.exe or javaw.exe) attempts to resolve the JNDI resource, resulting in an outbound network connection to a specified port (389, 636, 1099, or 1389).
4.  The Java process makes a connection to a malicious LDAP or RMI server controlled by the attacker.
5.  The malicious server provides a Java class file containing malicious code.
6.  The vulnerable Java process downloads the malicious Java class file.
7.  The Java process executes the downloaded malicious code.
8.  The attacker achieves remote code execution on the targeted system.

## Impact

Successful exploitation of the Log4j vulnerability (CVE-2021-44228) can lead to remote code execution, allowing attackers to gain complete control over affected systems. This can result in data breaches, system compromise, and further lateral movement within the network. The vulnerability affected numerous organizations across various sectors, making it a critical threat for defenders to address. Unpatched systems are at high risk of compromise.

## Recommendation

*   Deploy the Sigma rule `Detect Java Outbound Connections to LDAP/RMI Ports` to identify potentially malicious network connections originating from Java processes (logsource: network_connection, process_creation).
*   Investigate and validate any alerts generated by the Sigma rule `Detect Java Outbound Connections to LDAP/RMI Ports` to determine if the connections are legitimate or indicative of exploitation (logsource: network_connection, process_creation).
*   Review and tune the provided Sigma rules, specifically adjusting the `outbound_network_connection_from_java_using_default_ports_filter`, to reduce false positives based on known legitimate Java applications in your environment.
*   Patch vulnerable Log4j instances to the latest version to remediate the vulnerability (CVE-2021-44228).
