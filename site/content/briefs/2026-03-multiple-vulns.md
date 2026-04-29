---
title: Multiple Vulnerabilities in Canva Affinity, TP-Link, and HikVision Devices
slug: 2026-03-multiple-vulns
description: Cisco Talos disclosed multiple vulnerabilities in Canva Affinity, TP-Link Archer AX53, and HikVision Ultra Face Recognition Terminal products which could lead to sensitive information disclosure, arbitrary code execution, or credentials leak if exploited.
date: "2026-03-27T14:35:00Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - vulnerability
  - code-execution
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1189
    technique_name: Drive-by Compromise
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Password Stores
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1018
    technique_name: Remote System Discovery
  - tactic_id: TA0008
    tactic_name: Lateral Movement
    technique_id: T1021
    technique_name: Remote Services
references:
  - https://blog.talosintelligence.com/tp-link-canva-hikvision-vulnerabilities/
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2311
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2310
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2300
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2319
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2321
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2314
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2298
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2299
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2317
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2316
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2318
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2324
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2301
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2320
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2325
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2315
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2313
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2312
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2297
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2290
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2283
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2284
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2285
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2286
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2287
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2288
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2289
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2294
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2291
  - https://talosintelligence.com/vulnerability_reports/TALOS-2025-2281
rules:
  - title: Detect Canva Affinity opening EMF files
    description: Detects processes opening EMF files which may indicate exploitation of Canva Affinity vulnerabilities.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - file_event
      - windows
  - title: Detect Network Traffic to TP-Link Routers on Port 22
    description: Detects network connections to TP-Link routers on port 22, which may indicate attempted exploitation of SSH vulnerabilities.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Hikvision SADP Traffic
    description: Detects network traffic associated with the Hikvision SADP protocol, potentially indicating attempts to exploit the SADP XML parsing vulnerability.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
rules_count: 3
---

Cisco Talos' Vulnerability Discovery & Research team recently disclosed a series of vulnerabilities affecting several popular software and hardware products. These include 19 vulnerabilities in Canva Affinity, a graphic and document design tool; 10 vulnerabilities in TP-Link Archer AX53, a dual-band gigabit Wi-Fi router; and one vulnerability in HikVision Ultra Face Recognition Terminals used for authentication. The identified issues range from out-of-bounds read vulnerabilities and type confusion in Canva Affinity to stack-based buffer overflows, out-of-bounds writes, and a misconfiguration vulnerability in TP-Link devices, and a stack-based buffer overflow in Hikvision. Successful exploitation of these vulnerabilities could allow attackers to execute arbitrary code, leak sensitive information, or compromise device credentials. All reported vulnerabilities have been patched by their respective vendors.

## Attack Chain

1.  **Initial Access (TP-Link & HikVision):** An attacker gains network access to a vulnerable TP-Link Archer AX53 router or HikVision Ultra Face Recognition Terminal.
2.  **Network Packet Crafting (TP-Link & HikVision):** The attacker crafts a malicious network packet specifically designed to exploit a buffer overflow or other vulnerability in the target device's firmware.
3.  **Packet Transmission (TP-Link & HikVision):** The crafted network packet is sent to the vulnerable device, targeting a specific service or functionality (e.g., the tdpServer SSH port update functionality in TP-Link or SADP XML parsing in HikVision).
4.  **Vulnerability Trigger (TP-Link & HikVision):** Upon receiving the malicious packet, the targeted service attempts to process it, triggering the vulnerability (e.g., a stack-based buffer overflow).
5.  **Code Execution or Memory Corruption (TP-Link & HikVision):** The buffer overflow or other vulnerability allows the attacker to overwrite memory, potentially leading to arbitrary code execution or corruption of critical system data.
6.  **Initial Access (Canva):** An attacker entices a user to open a malicious EMF file using Canva Affinity.
7.  **File Parsing (Canva):** Canva Affinity attempts to parse the EMF file.
8.  **Exploitation (Canva):** The malformed EMF triggers an out-of-bounds read or type confusion vulnerability, allowing the attacker to read sensitive data or execute code.

## Impact

Successful exploitation of the reported vulnerabilities could have significant consequences. In the case of Canva Affinity, attackers could potentially disclose sensitive information. For TP-Link devices, attackers could gain control of the router, potentially compromising network security and allowing for man-in-the-middle attacks or other malicious activities. In HikVision devices, successful exploitation leads to remote code execution. Given the widespread use of these devices, a successful widespread attack could impact a large number of users and organizations.

## Recommendation

*   Apply the latest security patches released by Canva, TP-Link, and HikVision to address the vulnerabilities mentioned in this brief (CVE-2025-64776, CVE-2025-64301, CVE-2025-64733, CVE-2025-66042, CVE-2025-62403, CVE-2025-58427, CVE-2025-62500, CVE-2025-61979, CVE-2025-61952, CVE-2025-47873, CVE-2025-66503, CVE-2026-20726, CVE-2025-66000, CVE-2025-65119, CVE-2026-22882, CVE-2025-66617, CVE-2025-66633, CVE-2025-64735, CVE-2025-66342, CVE-2025-62673, CVE-2025-59482, CVE-2025-62405, CVE-2025-59487, CVE-2025-61983, CVE-2025-62404, CVE-2025-61944, CVE-2025-58455, CVE-2025-58077, CVE-2025-62501, CVE-2025-66176).
*   Monitor network traffic for suspicious packets targeting TP-Link Archer AX53 routers using a network intrusion detection system (NIDS). Consider creating custom signatures to detect exploitation attempts related to TALOS-2025-2290, TALOS-2025-2283, TALOS-2025-2284, TALOS-2025-2285, TALOS-2025-2286, TALOS-2025-2287, TALOS-2025-2288, TALOS-2025-2289, TALOS-2025-2294, and TALOS-2025-2291.
*   Monitor endpoint systems for processes opening EMF files, particularly if the process is Canva Affinity, to detect potential exploitation of Canva Affinity vulnerabilities (TALOS-2025-2311, TALOS-2025-2310, TALOS-2025-2300, TALOS-2025-2319, TALOS-2025-2321, TALOS-2025-2314, TALOS-2025-2298, TALOS-2025-2299, TALOS-2025-2317, TALOS-2025-2316, TALOS-2025-2318, TALOS-2025-2324, TALOS-2025-2301, TALOS-2025-2320, TALOS-2025-2325, TALOS-2025-2315, TALOS-2025-2313, TALOS-2025-2312, TALOS-2025-2297).
