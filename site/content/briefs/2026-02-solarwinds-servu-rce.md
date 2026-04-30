---
title: Critical Vulnerabilities in SolarWinds Serv-U Allow Remote Code Execution
slug: 2026-02-solarwinds-servu-rce
description: Multiple critical vulnerabilities in SolarWinds Serv-U MFT and FTP Server allow remote code execution, potentially leading to system compromise.
date: "2026-02-26T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - solarwinds
  - serv-u
  - rce
  - vulnerability
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Execution
    technique_id: T1059.001
    technique_name: 'Command and Scripting Interpreter: PowerShell'
references:
  - https://ccb.belgium.be/advisories/warning-critical-vulnerabilities-solarwinds-serv-u-servers-can-be-exploited-remote-code
  - https://documentation.solarwinds.com/en/success_center/servu/content/release_notes/servu_15-5-4_release_notes.htm
  - https://www.solarwinds.com/trust-center/security-advisories/cve-2025-40538
  - https://www.solarwinds.com/trust-center/security-advisories/cve-2025-40539
  - https://www.solarwinds.com/trust-center/security-advisories/cve-2025-40540
  - https://www.solarwinds.com/trust-center/security-advisories/cve-2025-40541
  - https://thehackernews.com/2026/02/solarwinds-patches-4-critical-serv-u.html
rules:
  - title: Suspicious Process Spawned by Serv-U
    description: Detects suspicious processes spawned by Serv-U processes, potentially indicating exploitation.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Serv-U Creating System Admin User (CVE-2025-40538)
    description: Detects creation of a system admin user, which could indicate exploitation of CVE-2025-40538.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - registry_set
      - windows
rules_count: 2
---

On February 25, 2026, the Centre for Cybersecurity Belgium (CCB) issued an advisory regarding four critical vulnerabilities (CVE-2025-40538, CVE-2025-40539, CVE-2025-40540, CVE-2025-40541) in SolarWinds Serv-U MFT and FTP Server. These vulnerabilities, if exploited, can lead to remote code execution (RCE) on the affected systems.  The Serv-U products are file transfer solutions widely used by organizations. While there's no current indication of active exploitation as of the advisory's release, the CCB anticipates potential exploitation attempts by threat actors, including ransomware groups, given their past interest in file transfer technologies. Exploitation on Windows deployments requires administrative privileges. The vulnerabilities affect SolarWinds Serv-U MFT and FTP Server.

## Attack Chain

1.  Attacker gains initial access to a Serv-U server, potentially through compromised credentials or other means.
2.  Attacker exploits CVE-2025-40538 (broken access control) to create a system administrator user. This may involve sending a specially crafted request to the Serv-U server.
3.  The attacker uses the newly created administrator account to gain administrative privileges.
4.  Attacker exploits CVE-2025-40539 (type confusion) or CVE-2025-40540 (type confusion) to inject and execute arbitrary code. This could involve sending further malicious requests.
5.  Alternatively, the attacker exploits CVE-2025-40541 (Insecure Direct Object Reference) to execute native code.
6.  The attacker executes arbitrary commands on the server with root privileges.
7.  The attacker establishes persistence via scheduled tasks or other mechanisms.
8.  The attacker moves laterally within the network, exfiltrates sensitive data, deploys ransomware, or performs other malicious activities.

## Impact

Successful exploitation of these vulnerabilities allows attackers to execute arbitrary code with root privileges on the affected SolarWinds Serv-U servers. This could lead to full system compromise, data theft, ransomware deployment, and disruption of file transfer services.  The scope could affect organizations relying on Serv-U for critical file transfers. The CCB advisory highlights potential targeting by ransomware groups who have shown past interest in file transfer technologies.

## Recommendation

*   Immediately patch SolarWinds Serv-U MFT and FTP Server to version 15.5.4 or later to remediate CVE-2025-40538, CVE-2025-40539, CVE-2025-40540, and CVE-2025-40541 (SolarWinds advisories).
*   Enable and review Sysmon process creation logs for suspicious processes spawned by Serv-U processes to detect potential exploitation attempts.
*   Implement network monitoring to detect unusual traffic originating from Serv-U servers, which might indicate command and control activity after successful exploitation.
