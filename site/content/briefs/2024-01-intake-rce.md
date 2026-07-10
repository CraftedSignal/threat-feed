---
title: Intake Package Remote Code Execution via Malicious Catalog
slug: 2024-01-intake-rce
description: A remote code execution vulnerability exists in Intake versions prior to 2.0.9 due to the automatic expansion of the `shell()` syntax within parameter default values during catalog parsing, allowing an attacker to execute arbitrary commands by loading a malicious catalog YAML file.
date: "2024-01-23T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - rce
  - vulnerability
  - intake
products:
  - Intake
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-33310
rules:
  - title: Detect Suspicious Intake Catalog Execution
    description: Detects suspicious processes spawned as child processes of python executing Intake, indicating potential RCE via catalog parsing.
    platform: sigma
    severity: critical
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious YAML Catalog File Access
    description: Detects access to YAML files with suspicious file paths, which may indicate a malicious catalog file being loaded
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566
    data_sources:
      - file_event
      - linux
rules_count: 2
---

The Intake package, used for data discovery and loading, contains a critical vulnerability (CVE-2026-33310) in versions prior to 2.0.9. This vulnerability stems from the automatic expansion of the `shell()` syntax within parameter default values when a catalog is parsed. Specifically, if a catalog YAML file contains a parameter default such as `shell(<command>)`, the enclosed command is executed by the system during the catalog parsing process. This allows an attacker to craft a malicious catalog YAML file containing arbitrary commands. If a user loads this malicious catalog using a vulnerable version of Intake, the embedded commands will execute on the host system, leading to remote code execution. This issue has been addressed in Intake version 2.0.9 by setting `getshell` to False by default, effectively disabling this dangerous behavior. This vulnerability poses a significant risk to systems using vulnerable Intake versions, as attackers could potentially gain full control over affected machines.

## Attack Chain

1.  Attacker crafts a malicious YAML catalog file. This file includes a parameter default value that utilizes the `shell()` syntax to inject arbitrary commands. For example, `shell(malicious_command)`.
2.  The attacker delivers the malicious YAML catalog file to the victim. This might involve social engineering or other means of tricking the user into using the file.
3.  The victim, running a vulnerable version of Intake (prior to 2.0.9), attempts to load the malicious catalog YAML file. This could be done through an Intake function call or a command-line tool.
4.  Intake parses the YAML catalog file. As it encounters the `shell()` syntax within the parameter default value, it automatically attempts to expand it.
5.  The embedded command within the `shell()` syntax is executed on the host system with the privileges of the user running the Intake process.
6.  The attacker gains arbitrary code execution on the victim's system. This could involve installing malware, creating new user accounts, or exfiltrating sensitive data.
7.  The attacker establishes persistence on the compromised system to maintain access, often by creating a scheduled task or modifying system startup scripts.
8.  The attacker performs lateral movement within the network, leveraging the compromised system to access other sensitive systems and data.

## Impact

Successful exploitation of CVE-2026-33310 allows an attacker to execute arbitrary commands on the system running the vulnerable Intake package. This can lead to complete system compromise, data theft, and potentially lateral movement within the network. The severity is high due to the ease of exploitation (simply loading a malicious YAML file) and the potential for significant damage. While the specific number of affected installations is unknown, organizations using Intake for data processing and analysis are at risk.

## Recommendation

*   Upgrade the Intake package to version 2.0.9 or later to mitigate CVE-2026-33310 (see Overview).
*   Implement strict validation and sanitization of any catalog YAML files loaded by Intake, even after upgrading, to prevent similar vulnerabilities (see Attack Chain).
*   Monitor process creation events for unexpected command execution originating from the Python interpreter or related Intake processes, using the provided Sigma rule (Detect Suspicious Intake Catalog Execution).
*   Enable file integrity monitoring for Intake catalog files to detect unauthorized modifications, which can be indicative of malicious activity.
