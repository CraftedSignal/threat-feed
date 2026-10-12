---
title: 'CVE-2022-45451: Local Arbitrary File Read and Potential LPE in Acronis ngscan.sys'
slug: 2026-10-acronis-ngscan-arbitrary-file-read
description: A local privilege escalation vulnerability (CVE-2022-45451) in the Acronis ngscan.sys minifilter driver allows low-privileged attackers to perform arbitrary file reads and interact with sensitive registry keys.
date: "2026-10-12T11:14:14Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:acronis:cyber_protect:15:*:*:*:*:*:*:*
  - cpe:2.3:a:acronis:agent:*:*:*:*:*:windows:*:*
  - cpe:2.3:a:acronis:cyber_protect:15:*:*:*:*:windows:*:*
  - cpe:2.3:a:acronis:cyber_protect_home_office:*:*:*:*:*:windows:*:*
tags:
  - privilege-escalation
  - arbitrary-file-read
  - driver-vulnerability
  - windows
vendors:
  - Acronis
products:
  - Acronis Agent (< 22.10)
  - Acronis Cyber Protect (= 15)
  - Acronis Cyber Protect Home Office (< 40173)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The driver improperly handles access control on filter communication ports, allowing local attackers... to perform arbitrary file reads... and potentially... local code execution.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: The driver supports... changing sensitive registry keys... that may lead to local code execution.
    confidence_band: high
cves:
  - id: CVE-2022-45451
    cvss: 7.8
    epss: 0.00512
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-ALFAROM256-CVE-2022-45451
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Acronis Agent to version 22.10 or later.
      owner: IT Operations
      due: 48h
      evidence: Source identifies Acronis Agent < 22.10 as affected.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Acronis Cyber Protect Home Office to 40173 or later.
      owner: IT Operations
      addresses: CVE-2022-45451
      evidence: Source identifies Acronis Cyber Protect Home Office < 40173 as affected.
---

CVE-2022-45451 is a vulnerability affecting the `ngscan.sys` minifilter driver included in multiple Acronis Cyber Protect products. The vulnerability stems from improper access control on the driver's filter communication ports. Specifically, the driver initializes communication ports with a default or NULL Discretionary Access Control List (DACL), which permits local, low-privileged processes to communicate with the driver.

An attacker can leverage this communication channel to request the creation of a "scan context" for any file on the system. Once the context is established, the driver returns a file descriptor for the requested resource, bypassing standard filesystem access restrictions. This enables arbitrary file reads, including sensitive system files like the Windows Security Account Manager (SAM) database. Furthermore, the driver exposes functions to manipulate specific registry keys, which researchers identified as a potential vector for achieving local code execution by targeting DLL injection mechanisms.

## Attack Chain

1. The attacker gains initial local access to a Windows system running a vulnerable version of Acronis Cyber Protect.
2. The attacker identifies the `ngscan.sys` driver's communication ports, which are created with improper DACLs (including NULL).
3. The attacker opens a communication handle to the driver by sending a specially crafted message header ("TrMs") to the identified filter communication port.
4. The attacker sends a request to the driver to create a "scan context" for a target system file, such as `C:\Windows\System32\config\SAM`.
5. The driver creates the context and returns an identification handle to the attacker's process.
6. The attacker uses the returned handle to open a file descriptor with read access to the restricted system file.
7. The attacker reads the contents of the target file, facilitating credential theft or further privilege escalation.
8. Optionally, the attacker interacts with the driver's registry manipulation functions to attempt DLL hijacking or injection to elevate privileges to SYSTEM.

## Impact

Successful exploitation allows a local, low-privileged user to read arbitrary files, including password hashes stored in the SAM database, which can be cracked offline to gain elevated credentials. Additionally, the potential for registry manipulation provides a direct path to full system compromise through code execution. The vulnerability affects a wide range of Acronis home and enterprise products.

## Recommendation

Prioritized, concrete actions for detection engineering teams:

* Patch affected systems to versions beyond the vulnerable range immediately (Acronis Agent >= 22.10, Acronis Cyber Protect Home Office >= 40173).
* Monitor for processes attempting to access sensitive registry keys or system configuration files (e.g., SAM, SYSTEM) that are typically only accessed by the SYSTEM account or specific administrative processes.
* Audit process handles for `ngscan.sys` communication ports if logging via kernel-level event tracing is available.
* Disable or restrict non-administrative access to the `ngscan.sys` filter communication ports if patching is delayed.
