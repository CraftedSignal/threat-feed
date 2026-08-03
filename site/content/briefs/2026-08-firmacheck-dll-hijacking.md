---
title: DLL Hijacking in FirmaCheck for Windows via Unvalidated OpenSSL Configuration
slug: 2026-08-firmacheck-dll-hijacking
description: FirmaCheck for Windows versions prior to 1.3.16 are susceptible to local privilege escalation and arbitrary code execution due to an unvalidated OpenSSL configuration file path.
date: "2026-08-03T22:49:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - dll-hijacking
  - local-privilege-escalation
vendors:
  - Zucchetti
products:
  - FirmaCheck
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547.001
    technique_name: 'Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder'
    evidence: Attackers can write a malicious OpenSSL configuration file referencing an attacker-controlled DLL to achieve code execution at startup process privilege level when FirmaCheck.exe runs automatically at system startup.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574.001
    technique_name: 'Hijack Execution Flow: DLL Search Order Hijacking'
    evidence: FirmaCheck for Windows before 1.3.16 contains a dll hijacking vulnerability that allows local attackers to execute arbitrary code by placing a crafted openssl.cnf file in the unvalidated C:\Program Files (x86)\Common Files\SSL\ directory path.
    confidence_band: high
cves:
  - id: CVE-2026-41447
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41447
  - https://www.vulncheck.com/advisories/firmacheck-dll-hijacking-via-unvalidated-openssl-configuration-path
rules:
  - title: Detect Suspicious openssl.cnf Creation in Common Files Path
    description: Detects the creation of openssl.cnf within the vulnerable directory path identified in CVE-2026-41447, which may indicate a DLL hijacking attempt.
    platform: sigma
    severity: high
    tactics:
      - persistence
      - privilege-escalation
    techniques:
      - T1547.001
      - T1574.001
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Deploy Sigma rule to detect file creation in the vulnerable path.
      owner: Detection Engineering
      due: 24h
      evidence: CVE-2026-41447
  mitigation_plan:
    - priority: immediate
      action: Upgrade FirmaCheck to version 1.3.16 or later.
      owner: IT Operations
      addresses: CVE-2026-41447
      evidence: NVD vulnerability disclosure
---

FirmaCheck for Windows, a document signing utility by Zucchetti, contains a DLL hijacking vulnerability (CVE-2026-41447) affecting all versions prior to 1.3.16. The vulnerability stems from the application's failure to properly validate the directory path when loading the OpenSSL configuration file (openssl.cnf). An attacker with local access to the system can place a maliciously crafted openssl.cnf file into the C:\Program Files (x86)\Common Files\SSL\ directory. When the FirmaCheck.exe process initializes, it inadvertently loads a DLL specified within the attacker-controlled configuration file. Because FirmaCheck.exe is configured to execute automatically upon system startup, this flaw allows a local attacker to achieve arbitrary code execution with the privileges of the startup process, facilitating persistence and privilege escalation.

## Attack Chain

1. Attacker gains local access to the target Windows system.
2. Attacker identifies the path C:\Program Files (x86)\Common Files\SSL\ as a writable location or utilizes elevated privileges to create the directory structure if it does not exist.
3. Attacker crafts a malicious openssl.cnf file configured to load an attacker-supplied DLL.
4. Attacker places the malicious openssl.cnf file into the target directory.
5. Attacker places the payload DLL on the system in a location referenced by the crafted configuration file.
6. The target system reboots or the user logs in, triggering the automatic execution of FirmaCheck.exe.
7. FirmaCheck.exe reads the malicious openssl.cnf file during its initialization sequence.
8. FirmaCheck.exe executes the malicious DLL, granting the attacker code execution at the process privilege level.

## Impact

Successful exploitation allows a local attacker to execute arbitrary code on the affected Windows host. This facilitates persistence, potential privilege escalation, and full compromise of the local machine. The vulnerability affects all users of FirmaCheck prior to version 1.3.16, primarily impacting organizations using this software for document management and digital signatures.

## Recommendation

Prioritized actions for detection and remediation:
- Upgrade FirmaCheck to version 1.3.16 or later immediately to patch CVE-2026-41447.
- Deploy the Sigma rule provided in this brief to monitor for unauthorized creation of openssl.cnf files in standard paths.
- Audit the C:\Program Files (x86)\Common Files\SSL\ directory for suspicious configuration files or unexpected DLL files if patching cannot be performed immediately.
