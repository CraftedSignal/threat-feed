---
title: Multiple Out-of-Bounds Write Vulnerabilities in Rockwell Automation Arena
slug: 2026-07-rockwell-arena-cves
description: Multiple out-of-bounds write vulnerabilities (CVE-2026-8085, CVE-2026-8312, CVE-2026-8313, CVE-2026-8314) in Rockwell Automation Arena versions prior to V17.00.01 could allow an attacker to execute arbitrary code by convincing a user to open a malicious file.
date: "2026-07-16T16:14:38Z"
lastmod: "2026-07-25T08:31:39Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:rockwellautomation:arena:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - ics
  - ot
  - memory-corruption
  - out-of-bounds-write
  - arbitrary-code-execution
  - critical-manufacturing
vendors:
  - Rockwell Automation
products:
  - Rockwell Automation Arena <=V17.00.00
  - Arena Simulation (<= 17.00.00)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An attacker could leverage this vulnerability to execute arbitrary code in the context of the current process by convincing a user to open a malicious file.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: An attacker could leverage this vulnerability to execute arbitrary code in the context of the current process by convincing a user to open a malicious file.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: execute arbitrary code in the context of the current process
    confidence_band: high
cves:
  - id: CVE-2026-8085
    cvss: 7.3
    epss: 0.0018
  - id: CVE-2026-8312
    cvss: 7.3
    epss: 0.0018
  - id: CVE-2026-8313
    cvss: 7.3
    epss: 0.0018
  - id: CVE-2026-8314
    cvss: 7.3
    epss: 0.0018
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-197-01
  - https://www.cve.org/CVERecord?id=CVE-2026-8085
  - https://www.cve.org/CVERecord?id=CVE-2026-8312
  - https://www.cve.org/CVERecord?id=CVE-2026-8313
  - https://www.cve.org/CVERecord?id=CVE-2026-8314
  - https://www.securityweek.com/rockwell-patches-code-execution-flaws-in-arena-simulation-software/
rules:
  - title: Detects Rockwell Automation Arena Exploitation - Unexpected Child Process
    description: Detects CVE-2026-8085, CVE-2026-8312, CVE-2026-8313, CVE-2026-8314 exploitation - Processes of Rockwell Automation Arena (model.exe, expmt.exe, linker.exe, siman.exe) launching suspicious or unexpected child processes, indicating arbitrary code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1204.002
    data_sources:
      - process_creation
      - windows
rules_count: 1
updates:
  - at: "2026-07-25T08:31:39Z"
    level: L1
    summary: new product
    sources:
      - securityweek
    source_urls:
      - https://www.securityweek.com/rockwell-patches-code-execution-flaws-in-arena-simulation-software/
---

CISA has released an advisory detailing multiple memory corruption vulnerabilities, specifically out-of-bounds writes, affecting Rockwell Automation Arena simulation software versions prior to V17.00.01. These vulnerabilities, tracked as CVE-2026-8085, CVE-2026-8312, CVE-2026-8313, and CVE-2026-8314, reside in core components such as `model.exe`, `expmt.exe`, `linker.exe`, and `siman.exe`. Successful exploitation requires an attacker to convince a user to open a specially crafted malicious file. Upon opening, the improper validation of user-supplied data can lead to an out-of-bounds write, enabling arbitrary code execution in the context of the user running the Arena application. This affects the critical manufacturing sector worldwide.

## Attack Chain

1. An attacker crafts a malicious file, such as a project or data file, designed to exploit an out-of-bounds write vulnerability within Rockwell Automation Arena.
2. The attacker uses social engineering or other means to convince a user to open this malicious file using an affected version of the Arena software.
3. The vulnerable Arena component (e.g., `model.exe`, `expmt.exe`, `linker.exe`, `siman.exe`) attempts to process the malicious file.
4. Due to improper input validation, the malicious file triggers an out-of-bounds write in the application's memory.
5. This memory corruption allows the attacker to execute arbitrary code within the context of the currently running Arena process.
6. The arbitrary code execution can then lead to further malicious activities, such as payload execution, persistence establishment, or data exfiltration.

## Impact

Successful exploitation of these vulnerabilities could result in arbitrary code execution on the affected system. This means an attacker could gain control over the system where Rockwell Automation Arena is running, potentially leading to data compromise, system disruption, or further infiltration into critical manufacturing environments. While specific victim numbers are not provided, Rockwell Automation Arena is widely deployed in Critical Manufacturing sectors globally, suggesting a broad potential impact if exploited. The CVSSv3 base score for these vulnerabilities is 7.8 (High).

## Recommendation

* Patch Rockwell Automation Arena immediately to version V17.00.01 or later to remediate CVE-2026-8085, CVE-2026-8312, CVE-2026-8313, and CVE-2026-8314.
* Enable process creation logging via Sysmon or similar tools to detect unusual child processes spawned by `model.exe`, `expmt.exe`, `linker.exe`, or `siman.exe` using the provided Sigma rule.
* Minimize network exposure for all control system devices and systems, ensuring they are not accessible from the internet, as recommended by CISA.
* Isolate control system networks and remote devices behind firewalls and segment them from business networks.
