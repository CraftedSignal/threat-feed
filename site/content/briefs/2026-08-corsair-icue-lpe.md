---
title: Local Privilege Escalation in Corsair iCUE via DLL Hijacking
slug: 2026-08-corsair-icue-lpe
description: Corsair iCUE v5.9.105 contains a DLL hijacking vulnerability (CVE-2024-22002) in the iCUEUpdateService, allowing local unprivileged users to achieve SYSTEM-level code execution.
date: "2026-08-29T17:46:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:corsair:icue:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - dll-hijacking
  - windows
  - cve-2024-22002
vendors:
  - Corsair
products:
  - iCUE (v5.9.105)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: The service executes cuepkg.exe with SYSTEM privileges, which attempts to load missing DLLs from a directory where unprivileged users have write access.
    confidence_band: high
cves:
  - id: CVE-2024-22002
    cvss: 7.8
    epss: 0.00438
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-0XKICKIT-ICUE_DLLHIJACK_LPE-CVE-2024-22002
rules:
  - title: Detect DLL Hijacking in Corsair iCUE cuepkg.exe
    description: Detects the creation of specific DLLs in the Corsair iCUE update directory which is a known vector for CVE-2024-22002
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1574.001
    data_sources:
      - file_event
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy Sigma rule to monitor for unauthorized file creation in iCUE directories
      owner: Detection Engineering
      due: 24h
      evidence: Source describes CVE-2024-22002 via file injection in cuepkg-1.2.6
  hunt_leads:
    - lead: Search for non-standard DLLs in Corsair installation directories
      technique_id: T1574.001
      data_needed:
        - File system inventory
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source identifies specific DLLs used for hijacking
  mitigation_plan:
    - priority: short_term
      action: Restrict write access to the C:\Program Files\Corsair\iCUE5\cuepkg-1.2.6\ folder for standard users
      owner: IT Operations
      addresses: CVE-2024-22002
      evidence: Source states that standard users have write access to this directory
---

Corsair iCUE v5.9.105 contains a high-severity local privilege escalation vulnerability, tracked as CVE-2024-22002. The vulnerability resides within the iCUEUpdateService, which spawns the 'cuepkg.exe' process with 'NT AUTHORITY\SYSTEM' privileges to handle software updates. During this process, 'cuepkg.exe' attempts to load specific DLLs from the installation subdirectory '\cuepkg-1.2.6'. 

The security flaw stems from insecure directory permissions that allow standard, unprivileged users to write files into this specific installation path. An attacker can place a malicious DLL (e.g., 'profapi.dll', 'MSASN1.dll', or 'NTASN1.dll') into the directory. When the 'iCUEUpdateService' triggers an update - either automatically or manually via the user interface - 'cuepkg.exe' loads the attacker-controlled library, executing arbitrary code with system-level privileges. This vulnerability enables a local user to compromise the integrity and confidentiality of the host operating system.

## Attack Chain

1. An unprivileged user identifies the writeable directory path: '%INSTALLDIR%\cuepkg-1.2.6'.
2. The attacker compiles a malicious DLL designed to perform unauthorized administrative actions (e.g., adding a user to the local Administrators group).
3. The attacker copies the malicious DLL into the target directory, masquerading as 'profapi.dll', 'MSASN1.dll', or 'NTASN1.dll'.
4. The attacker triggers the iCUE update mechanism by launching the Corsair iCUE application or manually selecting "Check for updates".
5. The 'iCUEUpdateService' initiates 'cuepkg.exe' to process the update.
6. 'cuepkg.exe' loads the malicious DLL from the local directory instead of the legitimate system folder.
7. The operating system executes the malicious code within the context of the 'cuepkg.exe' process running as 'NT AUTHORITY\SYSTEM'.
8. The attacker gains full system control, such as privilege escalation to local Administrator.

## Impact

Successful exploitation of CVE-2024-22002 allows a local, low-privileged user to gain full SYSTEM privileges on the affected Windows workstation. This impacts the security posture of the host, enabling total system compromise, exfiltration of sensitive data, and persistence. Given the high popularity of Corsair iCUE among gaming and enthusiast users, many systems are potentially at risk.

## Recommendation

Prioritized actions for security teams:
- Identify and audit systems running Corsair iCUE v5.9.105 for insecure file permissions in the installation directory.
- Monitor process creation logs for 'cuepkg.exe' activity, specifically inspecting the working directory for unexpected DLL loading.
- Deploy the provided Sigma rule to detect suspicious file creation events in the iCUE installation path.
- Upgrade Corsair iCUE software to the latest version immediately once a patch is provided by the vendor.
