---
title: Path Traversal Vulnerability in NitroShare Desktop (CVE-2026-66050)
slug: 2026-07-nitroshare-path-traversal
description: NitroShare Desktop versions up to and including 0.3.4 are vulnerable to a path traversal flaw in their LAN file transfer server, allowing unauthenticated attackers on the same network to craft malicious filenames containing directory traversal sequences within the JSON item header. Exploiting this, attackers can write arbitrary files outside the intended transfer root to any location the current user has write access, including the Windows Startup folder, leading to persistent code execution upon user login.
date: "2026-07-27T15:18:54Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - persistence
  - code-execution
  - vulnerability
vendors:
  - NitroShare
products:
  - NitroShare Desktop <= 0.3.4
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Attackers can exploit the lack of path validation to write files outside the transfer root directory to arbitrary locations the current user has write access, including the Windows Startup folder, enabling persistent code execution on the next user login.
    confidence_band: high
cves:
  - id: CVE-2026-66050
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66050
rules:
  - title: Detects CVE-2026-66050 Exploitation - File Write to Startup Folder
    description: Detects CVE-2026-66050 exploitation by identifying file creations in common Windows Startup folders, which can be used for persistence. This rule targets the placement of arbitrary files via the path traversal vulnerability.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1547.001
    data_sources:
      - file_event
      - windows
rules_count: 1
---

A significant path traversal vulnerability, tracked as CVE-2026-66050, affects NitroShare Desktop versions through 0.3.4. The flaw resides within the application's LAN file transfer server, allowing unauthenticated attackers operating on the same local network to exploit a lack of path validation. By crafting a malicious filename that includes directory traversal sequences within the JSON item header name field, an attacker can write arbitrary files to locations outside the intended transfer root directory. This means that if the current user has write permissions to a sensitive directory, such as the Windows Startup folder, an attacker can place a malicious executable there. Upon the next user login or system restart, this executable will be automatically executed, granting the attacker persistent code execution on the compromised system. This vulnerability poses a high risk due to its unauthenticated nature and potential for persistent compromise.

## Attack Chain

1. An unauthenticated attacker, located on the same local area network (LAN) as a victim running NitroShare Desktop, identifies the vulnerable service.
2. The attacker crafts a specially designed filename payload containing directory traversal sequences (e.g., `../../../../ProgramData/Microsoft/Windows/Start Menu/Programs/Startup/malicious.exe`) within the JSON item header.
3. This malicious filename and the accompanying file payload are sent to the NitroShare LAN file transfer server as part of a file transfer request.
4. Due to the path traversal vulnerability (CVE-2026-66050), the NitroShare server fails to properly validate the path.
5. NitroShare writes the incoming file payload to the arbitrary path specified by the attacker, such as the Windows Startup folder.
6. Upon the next user logon or system reboot, the malicious executable placed in the Startup folder is automatically executed by the operating system.
7. The attacker achieves persistent code execution on the victim's system, allowing for further compromise or control.

## Impact

Successful exploitation of CVE-2026-66050 allows an unauthenticated attacker on the same local network to achieve persistent code execution on a vulnerable Windows system. The primary impact is the ability to write arbitrary files to any location the NitroShare service's user context has write access. This can be leveraged to place malicious executables in critical system startup locations, such as the Windows Startup folder (e.g., `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` or `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`), ensuring the malware runs every time the user logs in. This grants the attacker a durable foothold, enabling further attacks such as data exfiltration, lateral movement, or ransomware deployment, without requiring user interaction beyond the initial network presence.

## Recommendation

* Patch CVE-2026-66050 immediately by updating NitroShare Desktop to a version past 0.3.4 once available.
* Deploy the Sigma rule "Detects CVE-2026-66050 Exploitation - File Write to Startup Folder" to your SIEM to detect suspicious file writes to critical persistence locations.
* Monitor `file_event` logs for suspicious file creations or modifications within Windows Startup directories (e.g., `C:\Users\<username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`).
* Implement network segmentation to restrict access to the LAN file transfer service, limiting the attack surface for unauthenticated attackers.
