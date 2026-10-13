---
title: Seagate Toolkit Installer DLL Hijacking Vulnerability (CVE-2025-9267)
slug: 2026-10-seagate-toolkit-dll-hijacking
description: CVE-2025-9267 is a DLL hijacking vulnerability in Seagate Toolkit installer versions prior to 2.35.0.6, allowing local attackers to achieve SYSTEM-level privilege escalation.
date: "2026-10-13T02:37:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:seagate:seagate_toolkit:*:*:*:*:*:*:*:*
vendors:
  - Seagate
products:
  - Seagate Toolkit (< 2.35.0.6)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: DLL hijacking in Seagate Toolkit Installer before 2.35.0.6 enables SYSTEM privilege escalation.
    confidence_band: high
cves:
  - id: CVE-2025-9267
    epss: 0.00253
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TIGER3080-CVE-2025-9267
  - https://nvd.nist.gov/vuln/detail/CVE-2025-9267
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Seagate Toolkit to version 2.35.0.6 or later.
      owner: IT Operations
      due: 48h
      evidence: Source explicitly identifies version 2.35.0.6 as the fixed release.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 2.35.0.6 or later.
      owner: IT Operations
      addresses: CVE-2025-9267
      evidence: Source documentation for CVE-2025-9267.
---

Seagate Toolkit installer versions prior to 2.35.0.6 are vulnerable to a DLL hijacking flaw, identified as CVE-2025-9267. The vulnerability stems from insecure DLL loading practices where the installer attempts to load libraries from the current working directory without validating their source or integrity. An attacker with local access can place a crafted, malicious DLL within a directory accessible to the user and redirect the installer to load this library during the installation process. By exploiting this behavior, an attacker can execute arbitrary code with the privileges of the user executing the installer, which often results in privilege escalation to the SYSTEM account. The issue is documented under CWE-426 and CWE-427, highlighting the reliance on insecure search paths for system library resolution.

## Attack Chain

1. Attacker identifies a target system where the Seagate Toolkit installer is to be executed.
2. Attacker prepares a malicious DLL designed to execute a secondary payload (e.g., a reverse shell) upon loading.
3. Attacker modifies the installation parameters or user environment to force the installer to operate within a directory controlled by the attacker.
4. Attacker places the malicious DLL into the target directory, naming it to match a legitimate library expected by the Seagate Toolkit installer.
5. The victim or attacker executes the Seagate Toolkit installer application.
6. The installer initiates, searches the current working directory for required libraries, and inadvertently loads the attacker-supplied DLL.
7. The malicious code inside the DLL executes with the security context of the installer process.
8. Final objective is achieved, granting the attacker SYSTEM-level persistence or remote command execution.

## Impact

Successful exploitation of CVE-2025-9267 enables a local attacker to escalate privileges to the SYSTEM level on Windows systems. This impact is significant for organizations that utilize Seagate storage solutions, as it provides a pathway for an attacker to bypass standard user restrictions and obtain full control over the compromised host. The exploit complexity is documented as low, and the availability of a public proof-of-concept (PoC) increases the likelihood of exploitation attempts against unpatched systems.

## Recommendation

* Immediately upgrade all instances of Seagate Toolkit to version 2.35.0.6 or later to address the vulnerable DLL loading behavior.
* Monitor for unexpected binary execution or library loads from user-writable directories, particularly when the parent process is a known software installer.
* Audit endpoint environments for users with elevated installation rights and restrict the ability to place or execute arbitrary files in directories associated with administrative software updates.
