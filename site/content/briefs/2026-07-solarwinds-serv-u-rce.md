---
title: Remote Code Execution Vulnerability in SolarWinds Serv-U (CVE-2026-28304)
slug: 2026-07-solarwinds-serv-u-rce
description: A critical remote code execution vulnerability (CVE-2026-28304) has been identified in SolarWinds Serv-U versions 15.5.4 HF1 and below, allowing an attacker with high privileges to execute arbitrary code remotely as root, posing a severe risk to affected systems, though with lower impact on Windows deployments.
date: "2026-07-21T16:19:10Z"
lastmod: "2026-07-21T16:28:41Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - privilege-escalation
  - vulnerability-exploitation
  - vulnerability
  - cve
  - improper-access-control
  - server
  - software-update
  - idor
  - account-takeover
  - server-software
vendors:
  - SolarWinds
products:
  - Serv-U (15.5.4 HF1 and below)
  - Serv-U (<= 15.5.4 HF1)
affected_os:
  - Windows
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: remote code execution vulnerability that, when exploited, can allow the arbitrary execution of code remotely as root.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: can allow the arbitrary execution of code remotely as root
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This would elevate a group’s access to system administrator and allow code execution as root.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: SolarWinds Serv-U is affected by an insecure direct object reference (IDOR) vulnerability that can lead to SMTP hijacking leading to arbitrary account takeover.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: arbitrary account takeover
    confidence_band: high
cves:
  - id: CVE-2026-28304
    cvss: 9.1
  - id: CVE-2026-28309
    cvss: 9.1
  - id: CVE-2026-28306
    cvss: 9.1
  - id: CVE-2026-28307
    cvss: 9.1
  - id: CVE-2026-28316
    cvss: 9.1
  - id: CVE-2026-28312
    cvss: 9.1
  - id: CVE-2026-28313
    cvss: 9.1
  - id: CVE-2026-28317
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28304
  - https://documentation.solarwinds.com/en/success_center/servu/content/release_notes/servu_2026-3_release_notes.htm
  - https://www.solarwinds.com/trust-center/security-advisories/CVE-2026-28304
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28306
  - https://www.solarwinds.com/trust-center/security-advisories/CVE-2026-28306
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28307
  - https://www.solarwinds.com/trust-center/security-advisories/CVE-2026-28307
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28309
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28312
  - https://www.solarwinds.com/trust-center/security-advisories/CVE-2026-28312
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28313
  - https://www.solarwinds.com/trust-center/security-advisories/CVE-2026-28313
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28316
  - https://nvd.nist.gov/vuln/detail/CVE-2026-28317
iocs:
  - type: url
    value: https://documentation.solarwinds.com/en/success_center/servu/content/release_notes/servu_2026-3_release_notes.htm
  - type: url
    value: https://www.solarwinds.com/trust-center/security-advisories/CVE-2026-28316
  - type: url
    value: https://www.solarwinds.com/trust-center/security-advisories/CVE-2026-28317
ioc_counts:
  url: 3
updates:
  - at: "2026-07-21T16:25:13Z"
    level: L2
    summary: added CVE-2026-28306 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-28309
  - at: "2026-07-21T16:26:50Z"
    level: L2
    summary: 'merged source coverage: SolarWinds Serv-U Privilege Escalation Vulnerability (CVE-2026-28312)'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-28312
  - at: "2026-07-21T16:27:59Z"
    level: L2
    summary: 'merged source coverage: SolarWinds Serv-U Insecure Direct Object Reference (IDOR) Leads to Account Takeover (CVE-2026-28313)'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-28313
  - at: "2026-07-21T16:28:24Z"
    level: L2
    summary: added CVE-2026-28312 +2
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-28316
  - at: "2026-07-21T16:28:41Z"
    level: L2
    summary: added CVE-2026-28317
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-28317
---

A critical remote code execution (RCE) vulnerability, identified as CVE-2026-28304, affects SolarWinds Serv-U File Transfer Protocol (FTP) server versions 15.5.4 HF1 and below. This flaw enables an attacker with high privileges to achieve arbitrary code execution remotely as the root user. While the vulnerability's impact is noted to be lower in Windows deployments, it presents a significant risk for full system compromise on other operating systems where "root" is a more powerful user. Given the nature of Serv-U, often used for critical file transfers, successful exploitation could lead to extensive data exfiltration, system integrity breaches, and service disruption. Defenders must prioritize patching to mitigate this severe risk. The specifics of the exploit, such as which high privilege allows the RCE, are not detailed in the NVD entry.

## Attack Chain

1. An attacker obtains high-privilege credentials for a SolarWinds Serv-U instance or the underlying operating system.
2. The attacker crafts and sends a malicious request to the vulnerable Serv-U application.
3. The Serv-U application, operating with elevated privileges, processes the malformed input.
4. CVE-2026-28304 is triggered, leading to a bypass of security controls and arbitrary code execution.
5. The attacker's payload executes with root privileges on the host system running Serv-U.
6. With root access, the attacker establishes persistence mechanisms, exfiltrates sensitive data, or disrupts critical services.

## Impact

Successful exploitation of CVE-2026-28304 grants an attacker remote code execution capabilities with root privileges. This level of access allows for complete control over the compromised Serv-U server, leading to potential full system compromise, data exfiltration of sensitive files, installation of additional malware or backdoors, and denial-of-service. While the NVD advisory notes a lower impact on Windows deployments, the "as root" designation suggests particularly severe consequences for Linux or Unix-based Serv-U installations, where root access provides unrestricted system control. Organizations using Serv-U for mission-critical operations or storing sensitive data are at high risk.

## Recommendation

* Immediately update SolarWinds Serv-U to version 15.5.4 HF2 or later to patch CVE-2026-28304, as specified in the SolarWinds advisory references.
* Implement strong authentication measures and principle of least privilege for Serv-U accounts to mitigate the prerequisite of high privilege credentials for exploitation.
* Monitor Serv-U application logs and system-level process creation logs (e.g., Sysmon on Windows, Auditd on Linux) for unusual activity indicating potential exploitation attempts or post-exploitation behavior.
* Review firewall rules to restrict network access to Serv-U instances to only necessary source IPs and ports, reducing the attack surface for remote exploitation.
