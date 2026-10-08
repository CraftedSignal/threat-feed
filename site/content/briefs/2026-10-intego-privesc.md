---
title: Local Privilege Escalation in Intego Antivirus for Windows
slug: 2026-10-intego-privesc
description: A link-following vulnerability in the optimization module of Intego Antivirus for Windows through 3.0.0.1 allows local attackers to achieve arbitrary file deletion and privilege escalation to SYSTEM.
date: "2026-10-08T22:07:51Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:intego:antivirus:*:*:*:*:*:windows:*:*
tags:
  - privilege-escalation
  - windows
  - vulnerability
vendors:
  - Intego
products:
  - Intego Antivirus for Windows (<= 3.0.0.1)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Intego Antivirus for Windows through 3.0.0.1 contains a link following vulnerability in its optimization module that allows local unprivileged users to delete arbitrary folders as SYSTEM.
    confidence_band: high
cves:
  - id: CVE-2026-107707
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107707
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Intego Antivirus for Windows to the latest available version.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-107707 vulnerability in versions <= 3.0.0.1
  mitigation_plan:
    - priority: immediate
      action: Upgrade Intego Antivirus for Windows
      owner: IT Operations
      addresses: CVE-2026-107707
      evidence: Source confirms vulnerability in versions 3.0.0.1 and earlier
---

Intego Antivirus for Windows versions 3.0.0.1 and earlier contain a critical link-following vulnerability within their optimization module. This flaw allows a local, unprivileged attacker to perform arbitrary file or directory deletions by abusing how the application handles file operations during the optimization process. By manipulating the filesystem environment, an attacker can trick the service into following a junction point to a sensitive location, such as C:\Config.msi. Through subsequent interaction with the Windows Installer rollback mechanism, the attacker can influence the system state to execute arbitrary code with SYSTEM-level privileges. This vulnerability represents a significant security risk for Windows environments where multiple users share local access, as it enables the escalation of local user accounts to full system administrative control.

## Attack Chain

1. Attacker identifies the optimization module in Intego Antivirus performing file operations on user-controlled directories.
2. Attacker prepares a malicious directory structure to be scanned or processed by the antivirus.
3. Attacker deletes a target file or folder that the optimization module expects to encounter.
4. Attacker creates a filesystem directory junction at the target location pointing to C:\Config.msi.
5. Attacker triggers the optimization module, causing the service to follow the junction with elevated SYSTEM privileges.
6. Attacker monitors for Windows Installer activity or triggers an installer rollback process.
7. Attacker leverages the hijacked installer context to execute arbitrary malicious binaries as SYSTEM.

## Impact

Successful exploitation of this vulnerability permits an unprivileged local attacker to gain full SYSTEM privileges on the affected Windows host. This facilitates complete system compromise, including credential theft, installation of persistent backdoors, and total control over the operating system environment. 

## Recommendation

Prioritize the upgrade of all Intego Antivirus for Windows installations to a version beyond 3.0.0.1 immediately, as no patch or workaround is currently described that mitigates the flaw without updating. 
