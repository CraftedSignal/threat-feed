---
brief_id: brief-2026-04-25-uat-4356-firestarter
event_id: brief-2026-04-25-uat-4356-firestarter
revision: 2
activity_at: "2026-11-20T01:37:27Z"
revision_history:
  - revision: 2
    at: "2026-11-20T01:37:27Z"
    checksum: sha256:1e4f5004f6753ecfa112e8987ec055c0784ee6bae6ed26ebf06f87d0cc60aae3
    summary: exploited:true; KEV CVE-2025-20333; KEV CVE-2025-20362
    changed_fields:
      - affected_products
      - cves
      - exploitation_evidence
      - iocs
      - lastmod
      - priority_score
      - priority_signals
      - references
      - ttps
      - updates
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
title: UAT-4356 FIRESTARTER Backdoor Targeting Cisco Firepower Devices
slug: 2026-04-uat-4356-firestarter
description: UAT-4356 is actively targeting Cisco Firepower devices running FXOS, exploiting CVE-2025-20333 and CVE-2025-20362 to deploy the FIRESTARTER backdoor which allows remote access and control by injecting malicious shellcode into the LINA process.
date: "2026-04-23T15:11:53Z"
lastmod: "2026-11-20T01:36:50Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - UAT-4356
exploited: true
exploitation_evidence:
  status: confirmed_active
  source_url: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  observed_at: "2025-09-25T00:00:00Z"
  confidence: high
tags:
  - uat-4356
  - firestarter
  - cisco
  - backdoor
  - network
  - espionage
vendors:
  - Cisco
products:
  - ASA
  - ASA 5500-X Series
  - Cisco ASA Software
  - Cisco Firepower 4100 Security Appliance
  - Cisco Firepower 9300 Security Appliance
  - Cisco IOS
  - Cisco IOS XE
  - Cisco IOS XR
  - Cisco Secure Firewall Threat Defense (FTD)
  - Firepower eXtensible Operating System (FXOS)
  - FTD
  - Secure Firewall ASA Software
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    subtechnique_id: T1547.004
    subtechnique_name: Winlogon Helper DLL
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    subtechnique_id: T1059.004
    subtechnique_name: Unix Shell
cves:
  - id: CVE-2025-20333
    cvss: 9.9
    epss: 0.25141
    kev: true
    kev_status: "true"
  - id: CVE-2025-20362
    cvss: 6.5
    epss: 0.44084
    kev: true
    kev_status: "true"
  - id: CVE-2025-20363
    cvss: 9
    epss: 0.0529
    kev_status: unknown
references:
  - https://blog.talosintelligence.com/uat-4356-firestarter/
  - https://cyber.gc.ca/en/alerts-advisories/al25-012-vulnerabilities-impacting-cisco-asa-ftd-devices-cve-2025-20333-cve-2025-20362-cve-2025-20363
iocs:
  - type: filename
    value: lina_cs
  - type: filename
    value: svc_samcore.log
ioc_counts:
  filename: 2
rules:
  - title: File Creation in Suspicious Directory
    description: Detects the creation of suspicious files often associated with the FIRESTARTER backdoor in directories commonly used by the malware.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1105
    data_sources:
      - file_event
      - linux
  - title: LINA Process Execution
    description: Detects the execution of the lina_cs process, which may indicate the presence of the FIRESTARTER backdoor.
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
updates:
  - at: "2026-05-07T07:59:40Z"
    level: L2
    summary: added CVE-2025-20363
    sources:
      - cccs
  - at: "2026-11-20T01:36:50Z"
    level: L3
    summary: exploited:true; KEV CVE-2025-20333; KEV CVE-2025-20362
    sources:
      - cisa-kev
    source_urls:
      - https://www.cisa.gov/known-exploited-vulnerabilities-catalog
---

## Overview

Cisco Talos reported that UAT-4356 continues to actively target Cisco Firepower devices running the Firepower eXtensible Operating System (FXOS). In early 2024, Cisco Talos attributed the ArcaneDoor campaign to UAT-4356, a state-sponsored actor focused on gaining access to network perimeter devices for espionage. The actor exploits n-day vulnerabilities CVE-2025-20333 and CVE-2025-20362 to gain unauthorized access to vulnerable devices. Upon successful exploitation, UAT-4356 deploys a custom-built backdoor called "FIRESTARTER," which shares technical capabilities with RayInitiator's Stage 3 shellcode. FIRESTARTER enables remote access and the execution of arbitrary code within the LINA process, a core component of Cisco's ASA and FTD appliances. This allows the attackers to maintain persistent access to compromised systems.

## Attack Chain

1.  UAT-4356 exploits CVE-2025-20333 and/or CVE-2025-20362 on Cisco Firepower devices running FXOS to gain initial access.
2.  The attacker manipulates the CSP_MOUNT_LIST to establish persistence for the FIRESTARTER backdoor.
3.  The FIRESTARTER backdoor is written to `/opt/cisco/platform/logs/var/log/svc_samcore.log` and the CSP_MOUNT_LIST is updated to copy itself to `/usr/bin/lina_cs`.
4.  After a graceful reboot, FIRESTARTER is executed from `/usr/bin/lina_cs`.
5.  FIRESTARTER restores the original CSP_MOUNT_LIST from `/tmp/CSP_MOUNTLIST.tmp` and removes the temporary copy and the trojanized `/usr/bin/lina_cs` file from disk.
6.  FIRESTARTER reads the LINA process’ memory, searching for specific byte sequences to verify memory layout.
7.  FIRESTARTER copies the next stage shellcode to the last 0x200 bytes of the "libstdc++.so" memory region.
8.  The attacker overwrites an internal data structure in the LINA process to replace a pointer to a legitimate WebVPN XML handler function with the address of the malicious shellcode. This allows execution of arbitrary shellcode received via WebVPN requests.

## Impact

Compromised Cisco Firepower devices allow UAT-4356 to gain a foothold on network perimeters for espionage. Successful exploitation and deployment of the FIRESTARTER backdoor enable attackers to execute arbitrary shellcode, potentially leading to data exfiltration, further network compromise, or disruption of services. The number of victims is currently unknown, but this campaign targets network perimeter devices, which could impact organizations across various sectors.

## Recommendation

*   Deploy the file integrity monitoring rule to detect the creation or modification of `/usr/bin/lina_cs` and `/opt/cisco/platform/logs/var/log/svc_samcore.log` (see "File Creation in Suspicious Directory").
*   Apply software upgrade recommendations outlined in Cisco's Security Advisory to mitigate CVE-2025-20333 and CVE-2025-20362.
*   Monitor network traffic for WebVPN requests containing unexpected XML payloads that might be used to trigger the FIRESTARTER backdoor.
