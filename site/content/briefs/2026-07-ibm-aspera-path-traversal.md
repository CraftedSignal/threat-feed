---
title: IBM Aspera Desktop App Path Traversal Vulnerability (CVE-2026-14973)
slug: 2026-07-ibm-aspera-path-traversal
description: The IBM Aspera Desktop App (versions 1.0.5 through 1.0.19) is affected by a path traversal vulnerability (CWE-22) which allows files to be written outside of the user's selected download destination, leading to high integrity and confidentiality impacts through arbitrary file write operations, and requires user interaction to exploit.
date: "2026-07-28T21:22:39Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - path-traversal
  - ibm
  - aspera
  - cve
  - critical-vulnerability
vendors:
  - IBM
products:
  - Aspera Desktop App (1.0.5)
  - Aspera Desktop App (1.0.19)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: 'CVSS vector includes UI:R (User Interaction: Required), which indicates an attacker must induce a user action, often achieved through phishing to initiate a malicious file transfer.'
    confidence_band: high
cves:
  - id: CVE-2026-14973
    cvss: 9.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14973
  - https://www.ibm.com/support/pages/node/7280939
---

A critical path traversal vulnerability, tracked as CVE-2026-14973 (CVSS 9.3), has been identified in the IBM Aspera Desktop App, affecting versions 1.0.5 through 1.0.19. This flaw, categorized as CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), allows an attacker to write files to arbitrary locations on a user's system, outside of the selected download destination. Exploitation of this vulnerability requires user interaction (UI:R), meaning an attacker must trick a user into initiating a malicious file transfer. Successful exploitation can lead to high confidentiality and integrity impacts, potentially enabling arbitrary code execution, persistence, and further system compromise through the placement of malicious files in sensitive directories. Defenders should prioritize patching and monitoring for unusual file write activity.

## Attack Chain

1. Attacker crafts a malicious file transfer request or a malformed file name containing path traversal sequences (e.g., `../../`) specifically designed to trigger CVE-2026-14973 in the IBM Aspera Desktop App.
2. The attacker induces a user to interact with this malicious transfer, for example, by tricking them into initiating a download or receiving a file through a spearphishing campaign.
3. The vulnerable IBM Aspera Desktop App, when processing the crafted input, fails to properly sanitize the file path due to the path traversal vulnerability (CWE-22).
4. Instead of writing the file to the user's designated download folder, the application writes it to an arbitrary, attacker-controlled location on the file system.
5. This arbitrary file write allows the attacker to place malicious executables, scripts, or configuration files in sensitive system directories (e.g., startup folders, program directories).
6. Upon subsequent system reboot, user login, or triggering of a system service, the arbitrarily placed malicious file is executed, achieving persistence or arbitrary code execution.
7. The successful execution of the malicious file leads to the attacker's final objective, which could include data exfiltration, further system compromise, or ransomware deployment.

## Impact

Successful exploitation of CVE-2026-14973 can lead to severe consequences for affected users. The ability to write files to arbitrary locations results in high integrity and confidentiality impacts. This allows an attacker to bypass standard file system permissions and place malicious executables or scripts in critical system directories. Such an action can facilitate arbitrary code execution, lead to data exfiltration, allow for persistent access, or enable ransomware deployment, ultimately compromising the entire system. No specific victim numbers or targeted sectors are currently available, but any user of the vulnerable IBM Aspera Desktop App is at risk.

## Recommendation

* Patch CVE-2026-14973 immediately by upgrading IBM Aspera Desktop App to a version greater than 1.0.19.
* Monitor process creation and file write events via your EDR or Sysmon logs for unusual activity originating from the IBM Aspera Desktop App processes, particularly writes to system directories or autostart locations outside of expected user download paths.
* Educate users about the risks of spearphishing and malicious file transfers, as user interaction is required for CVE-2026-14973 exploitation.
