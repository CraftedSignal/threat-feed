---
title: Multiple Vulnerabilities in Schneider Electric PowerChute Serial Shutdown
slug: 2026-07-schneider-electric-powerchute-vulnerabilities
description: Multiple vulnerabilities, including CVE-2026-2399, CVE-2026-2404, CVE-2026-2405, CVE-2026-2403, CVE-2026-2400, and CVE-2026-2401, in Schneider Electric PowerChute Serial Shutdown versions 1.4 and prior could allow attackers with adjacent network access and high privileges to overwrite critical system files via path traversal, forge or inject malicious log data, gain unauthorized account access through excessive authentication attempts, trigger denial-of-service conditions, or expose sensitive information.
date: "2026-07-09T15:56:37Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:schneider-electric:powerchute_serial_shutdown:*:*:*:*:*:*:*:*
tags:
  - ics
  - ot
  - vulnerability
  - path-traversal
  - crlf-injection
  - dos
  - log-tampering
  - critical-infrastructure
vendors:
  - Schneider Electric
  - SuSE
  - Red Hat
  - Microsoft
products:
  - PowerChute Serial Shutdown (<=1.4)
affected_os:
  - Windows
  - Red Hat Enterprise Linux
  - SuSE Linux
mitre_ttps:
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1490
    technique_name: Inhibit System Recovery
    evidence: PowerChute is vulnerable to improper restriction of file paths, which could allow critical system files to be overwritten with unintended data.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: ""
    evidence: Successful exploitation of these vulnerabilities could allow attackers to forge or inject malicious log data
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: ""
    evidence: Improper Restriction of Excessive Authentication Attempts
    confidence_band: high
  - tactic_id: TA0008
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Successful exploitation of these vulnerabilities could allow attackers to trigger denial‑of‑service conditions
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
    evidence: Successful exploitation of these vulnerabilities could allow attackers to expose sensitive information.
    confidence_band: high
cves:
  - id: CVE-2026-2399
    cvss: 6.1
    epss: 0.00204
  - id: CVE-2026-2405
    cvss: 6.5
    epss: 0.00245
  - id: CVE-2026-2403
    cvss: 4.3
    epss: 0.0017
  - id: CVE-2026-2400
    cvss: 4.3
    epss: 0.0023
  - id: CVE-2026-2401
    cvss: 5
    epss: 0.00103
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-190-02
  - https://www.cve.org/CVERecord?id=CVE-2026-2399
  - https://www.cve.org/CVERecord?id=CVE-2026-2404
  - https://www.cve.org/CVERecord?id=CVE-2026-2405
  - https://www.cve.org/CVERecord?id=CVE-2026-2403
  - https://www.cve.org/CVERecord?id=CVE-2026-2400
  - https://www.cve.org/CVERecord?id=CVE-2026-2401
  - https://www.se.com/ww/en/download/document/SPD-PCSS_WIN_EN/
  - https://www.se.com/ww/en/download/document/SPD-PCSS_LNX_EN/
  - https://download.schneider-electric.com/files?p_Doc_Ref=SPD_CCON-PCSSSH_EN
  - https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-104-01&p_enDocType=Security+and+Safety+Notice&p_File_Name=SEVD-2026-104-01.pdf
  - https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-104-01&p_enDocType=Security+and+Safety+Notice&p_File_Name=sevd-2026-104-01.json
---

CISA has issued an advisory regarding multiple vulnerabilities affecting Schneider Electric PowerChute Serial Shutdown software, versions 1.4 and prior. These vulnerabilities, including CVE-2026-2399 (Path Traversal), CVE-2026-2404 (Improper Output Encoding), CVE-2026-2405 (Excessive Authentication Attempts), CVE-2026-2403 (Uncontrolled Resource Consumption), CVE-2026-2400 (Improper Input Validation), and CVE-2026-2401 (CRLF Injection and Sensitive Information in Log), pose significant risks. Successful exploitation could lead to critical system file overwrites, log data manipulation, unauthorized account access, denial-of-service, and sensitive information exposure. The affected software is deployed globally across critical infrastructure sectors such as Communications, Critical Manufacturing, Energy, Healthcare, Information Technology, and Transportation Systems. While no active exploitation has been reported, the potential impact on critical operations necessitates immediate attention from defenders.

## Attack Chain

1. An attacker gains adjacent network access to the host running Schneider Electric PowerChute Serial Shutdown (implied by CVSS AV:A).
2. The attacker acquires high-privilege credentials for the PowerChute application (implied by CVSS PR:H).
3. Leveraging CVE-2026-2399, the attacker crafts a malicious input string containing path traversal sequences (e.g., `../../`) targeting PowerChute's file handling functions.
4. The crafted input is submitted through an authenticated interface, leading to the overwrite of critical system files or unauthorized file creation.
5. Through CVE-2026-2404 and CVE-2026-2401, the attacker injects malformed data into a PowerChute input field to exploit improper output encoding or CRLF injection.
6. This causes PowerChute to log the crafted data, potentially leading to log file poisoning, tampering, or injection of malicious content.
7. Exploiting CVE-2026-2403 or CVE-2026-2400, the attacker triggers conditions that lead to uncontrolled resource consumption or malformed input processing, causing a denial-of-service (DoS) on the PowerChute application.
8. The attacker attempts to reset user credentials by repeatedly triggering authentication attempts (CVE-2026-2405) or exfiltrates sensitive information exposed in manipulated log files (CVE-2026-2401).

## Impact

The successful exploitation of these vulnerabilities could have severe consequences for organizations relying on Schneider Electric PowerChute Serial Shutdown. Attackers could gain unauthorized control over critical system files, leading to system instability, data corruption, or even complete system compromise. Log data manipulation could hinder forensic analysis and incident response efforts, while denial-of-service attacks could disrupt critical operations, particularly in sectors like Energy and Manufacturing where PowerChute manages UPS systems. Exposure of sensitive information could lead to further compromise or compliance violations. The vulnerabilities affect systems worldwide, making the potential for widespread disruption significant if not patched.

## Recommendation

* Immediately update Schneider Electric PowerChute Serial Shutdown to version 1.5 or later to address CVE-2026-2399, CVE-2026-2404, CVE-2026-2405, CVE-2026-2403, CVE-2026-2400, and CVE-2026-2401.
* Review the Schneider Electric Security Handbook referenced in the advisory (https://download.schneider-electric.com/files?p_Doc_Ref=SPD_CCON-PCSSSH_EN) for specific hardening guidelines and mitigation strategies applicable to your environment.
* Ensure proper network segmentation to limit adjacent network access to PowerChute Serial Shutdown installations, as specified by the CVSS vector (AV:A).
* Implement strong authentication policies and monitor for excessive authentication attempts, which could indicate exploitation of CVE-2026-2405.
