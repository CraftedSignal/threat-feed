---
title: PaperCut NG/MF Improper Authentication Vulnerability (CVE-2023-27351)
slug: 2024-01-03-papercut-auth-bypass
description: CVE-2023-27351 is an improper authentication vulnerability in PaperCut NG/MF that allows remote attackers to bypass authentication via the SecurityRequestFilter class, leading to potential ransomware deployment.
date: "2024-01-03T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - papercut
  - authentication-bypass
  - ransomware
  - cve-2023-27351
vendors:
  - PaperCut
products:
  - NG/MF
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2023-27351
    cvss: 7.5
    epss: 0.86957
references:
  - https://www.cve.org/CVERecord?id=CVE-2023-27351
  - https://www.papercut.com/kb/Main/PO-1216-and-PO-1219
  - https://nvd.nist.gov/vuln/detail/CVE-2023-27351
rules:
  - title: Detect PaperCut Authentication Bypass Attempt (CVE-2023-27351)
    description: Detects potential exploitation attempts of CVE-2023-27351 by monitoring HTTP requests targeting the SecurityRequestFilter class.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious File Uploads After PaperCut Auth Bypass
    description: Detects suspicious file uploads to the PaperCut server after a potential authentication bypass.  Focuses on common web server upload directories.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1105
    data_sources:
      - file_event
      - linux
rules_count: 2
---

CVE-2023-27351 is a critical improper authentication vulnerability affecting PaperCut NG/MF. The vulnerability exists within the SecurityRequestFilter class, enabling remote attackers to bypass authentication mechanisms. This bypass can lead to unauthorized access to sensitive functionalities within the PaperCut NG/MF application. Publicly available reports indicate that this vulnerability is being actively exploited, including instances of ransomware deployment following successful exploitation. Due to the ease of exploitation and the potentially severe consequences, organizations using affected versions of PaperCut NG/MF are urged to apply mitigations immediately.

## Attack Chain

1.  Attacker identifies a vulnerable PaperCut NG/MF instance accessible over the network.
2.  The attacker crafts a malicious HTTP request targeting the SecurityRequestFilter class.
3.  The crafted request exploits the improper authentication vulnerability (CVE-2023-27351), bypassing normal authentication checks.
4.  Upon successful authentication bypass, the attacker gains unauthorized access to the PaperCut NG/MF application with elevated privileges.
5.  The attacker leverages the gained access to upload malicious scripts or binaries to the PaperCut server.
6.  The attacker executes the uploaded payload, initiating the ransomware encryption process or other malicious activities.
7.  Ransomware encrypts sensitive data on the PaperCut server and potentially spreads to other connected systems.
8.  The attacker demands a ransom payment for the decryption key.

## Impact

Successful exploitation of CVE-2023-27351 allows attackers to bypass authentication, gain unauthorized access, and potentially deploy ransomware. This can result in significant data loss, disruption of print services, and financial losses due to ransom demands and recovery efforts. The vulnerability is known to be actively exploited, increasing the risk to organizations using affected PaperCut NG/MF installations.

## Recommendation

*   Apply mitigations provided by PaperCut, referencing their knowledge base articles PO-1216 and PO-1219.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts against the SecurityRequestFilter class.
*   Follow applicable BOD 22-01 guidance for cloud services if the PaperCut instance is cloud-hosted.
