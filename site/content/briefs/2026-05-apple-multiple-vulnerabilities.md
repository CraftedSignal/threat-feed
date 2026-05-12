---
title: Multiple Vulnerabilities in Apple Products Allow for Arbitrary Code Execution, Privilege Escalation, and Data Confidentiality Compromise
slug: 2026-05-apple-multiple-vulnerabilities
description: Multiple vulnerabilities in Apple products could allow an attacker to execute arbitrary code, escalate privileges, and compromise data confidentiality.
date: "2026-05-12T14:13:13Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - apple
  - code execution
  - privilege escalation
  - data breach
vendors:
  - Apple
products:
  - iOS
  - iPadOS
  - macOS Sequoia
  - macOS Sonoma
  - macOS Tahoe
  - tvOS
  - visionOS
  - watchOS
affected_os:
  - iOS
  - iPadOS
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
cves:
  - id: CVE-2026-28922
  - id: CVE-2026-28925
  - id: CVE-2026-28943
  - id: CVE-2026-28958
  - id: CVE-2026-28986
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0563/
  - https://support.apple.com/en-us/127110
  - https://support.apple.com/en-us/127111
  - https://support.apple.com/en-us/127112
  - https://support.apple.com/en-us/127113
  - https://support.apple.com/en-us/127114
  - https://support.apple.com/en-us/127115
  - https://support.apple.com/en-us/127116
  - https://support.apple.com/en-us/127117
  - https://support.apple.com/en-us/127118
  - https://support.apple.com/en-us/127119
  - https://support.apple.com/en-us/127120
  - https://www.cve.org/CVERecord?id=CVE-2025-43524
  - https://www.cve.org/CVERecord?id=CVE-2026-1837
  - https://www.cve.org/CVERecord?id=CVE-2026-28819
  - https://www.cve.org/CVERecord?id=CVE-2026-28840
  - https://www.cve.org/CVERecord?id=CVE-2026-28846
  - https://www.cve.org/CVERecord?id=CVE-2026-28847
  - https://www.cve.org/CVERecord?id=CVE-2026-28848
  - https://www.cve.org/CVERecord?id=CVE-2026-28870
  - https://www.cve.org/CVERecord?id=CVE-2026-28872
  - https://www.cve.org/CVERecord?id=CVE-2026-28873
  - https://www.cve.org/CVERecord?id=CVE-2026-28877
  - https://www.cve.org/CVERecord?id=CVE-2026-28878
  - https://www.cve.org/CVERecord?id=CVE-2026-28882
  - https://www.cve.org/CVERecord?id=CVE-2026-28883
  - https://www.cve.org/CVERecord?id=CVE-2026-28894
  - https://www.cve.org/CVERecord?id=CVE-2026-28897
  - https://www.cve.org/CVERecord?id=CVE-2026-28901
  - https://www.cve.org/CVERecord?id=CVE-2026-28902
  - https://www.cve.org/CVERecord?id=CVE-2026-28903
  - https://www.cve.org/CVERecord?id=CVE-2026-28904
  - https://www.cve.org/CVERecord?id=CVE-2026-28905
  - https://www.cve.org/CVERecord?id=CVE-2026-28906
  - https://www.cve.org/CVERecord?id=CVE-2026-28907
  - https://www.cve.org/CVERecord?id=CVE-2026-28908
  - https://www.cve.org/CVERecord?id=CVE-2026-28913
  - https://www.cve.org/CVERecord?id=CVE-2026-28914
  - https://www.cve.org/CVERecord?id=CVE-2026-28915
  - https://www.cve.org/CVERecord?id=CVE-2026-28917
  - https://www.cve.org/CVERecord?id=CVE-2026-28918
  - https://www.cve.org/CVERecord?id=CVE-2026-28919
  - https://www.cve.org/CVERecord?id=CVE-2026-28920
  - https://www.cve.org/CVERecord?id=CVE-2026-28922
  - https://www.cve.org/CVERecord?id=CVE-2026-28923
  - https://www.cve.org/CVERecord?id=CVE-2026-28924
  - https://www.cve.org/CVERecord?id=CVE-2026-28925
  - https://www.cve.org/CVERecord?id=CVE-2026-28929
  - https://www.cve.org/CVERecord?id=CVE-2026-28930
  - https://www.cve.org/CVERecord?id=CVE-2026-28936
  - https://www.cve.org/CVERecord?id=CVE-2026-28940
  - https://www.cve.org/CVERecord?id=CVE-2026-28941
  - https://www.cve.org/CVERecord?id=CVE-2026-28942
  - https://www.cve.org/CVERecord?id=CVE-2026-28943
  - https://www.cve.org/CVERecord?id=CVE-2026-28944
  - https://www.cve.org/CVERecord?id=CVE-2026-28946
  - https://www.cve.org/CVERecord?id=CVE-2026-28947
  - https://www.cve.org/CVERecord?id=CVE-2026-28950
  - https://www.cve.org/CVERecord?id=CVE-2026-28951
  - https://www.cve.org/CVERecord?id=CVE-2026-28952
  - https://www.cve.org/CVERecord?id=CVE-2026-28953
  - https://www.cve.org/CVERecord?id=CVE-2026-28954
  - https://www.cve.org/CVERecord?id=CVE-2026-28955
  - https://www.cve.org/CVERecord?id=CVE-2026-28956
  - https://www.cve.org/CVERecord?id=CVE-2026-28957
  - https://www.cve.org/CVERecord?id=CVE-2026-28958
  - https://www.cve.org/CVERecord?id=CVE-2026-28959
  - https://www.cve.org/CVERecord?id=CVE-2026-28961
  - https://www.cve.org/CVERecord?id=CVE-2026-28962
  - https://www.cve.org/CVERecord?id=CVE-2026-28963
  - https://www.cve.org/CVERecord?id=CVE-2026-28964
  - https://www.cve.org/CVERecord?id=CVE-2026-28965
  - https://www.cve.org/CVERecord?id=CVE-2026-28969
  - https://www.cve.org/CVERecord?id=CVE-2026-28971
  - https://www.cve.org/CVERecord?id=CVE-2026-28972
  - https://www.cve.org/CVERecord?id=CVE-2026-28974
  - https://www.cve.org/CVERecord?id=CVE-2026-28976
  - https://www.cve.org/CVERecord?id=CVE-2026-28977
  - https://www.cve.org/CVERecord?id=CVE-2026-28978
  - https://www.cve.org/CVERecord?id=CVE-2026-28983
  - https://www.cve.org/CVERecord?id=CVE-2026-28985
  - https://www.cve.org/CVERecord?id=CVE-2026-28986
  - https://www.cve.org/CVERecord?id=CVE-2026-28987
  - https://www.cve.org/CVERecord?id=CVE-2026-28988
  - https://www.cve.org/CVERecord?id=CVE-2026-28990
  - https://www.cve.org/CVERecord?id=CVE-2026-28991
  - https://www.cve.org/CVERecord?id=CVE-2026-28992
  - https://www.cve.org/CVERecord?id=CVE-2026-28993
  - https://www.cve.org/CVERecord?id=CVE-2026-28994
  - https://www.cve.org/CVERecord?id=CVE-2026-28995
  - https://www.cve.org/CVERecord?id=CVE-2026-28996
  - https://www.cve.org/CVERecord?id=CVE-2026-39869
  - https://www.cve.org/CVERecord?id=CVE-2026-39870
  - https://www.cve.org/CVERecord?id=CVE-2026-39871
  - https://www.cve.org/CVERecord?id=CVE-2026-43652
  - https://www.cve.org/CVERecord?id=CVE-2026-43653
  - https://www.cve.org/CVERecord?id=CVE-2026-43654
  - https://www.cve.org/CVERecord?id=CVE-2026-43655
  - https://www.cve.org/CVERecord?id=CVE-2026-43656
  - https://www.cve.org/CVERecord?id=CVE-2026-43658
  - https://www.cve.org/CVERecord?id=CVE-2026-43659
  - https://www.cve.org/CVERecord?id=CVE-2026-43660
  - https://www.cve.org/CVERecord?id=CVE-2026-43661
  - https://www.cve.org/CVERecord?id=CVE-2026-43666
  - https://www.cve.org/CVERecord?id=CVE-2026-43668
rules:
  - title: Detect Suspicious Process Execution with Unsigned Apple Executables
    description: Detects execution of unsigned Apple executables, which might indicate exploitation of vulnerabilities like those described in CERTFR-2026-AVI-0563.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - macos
  - title: Detect Suspicious File Creation in Apple System Directories
    description: Detects the creation of new files in sensitive Apple system directories, which could indicate malware installation or exploitation activity related to CERTFR-2026-AVI-0563.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1547.004
    data_sources:
      - file_event
      - macos
rules_count: 2
---

On May 12, 2026, CERT-FR published an advisory regarding multiple vulnerabilities affecting various Apple products. These vulnerabilities, detailed in Apple security bulletins 127110 through 127120, could allow a remote attacker to perform arbitrary code execution, escalate privileges, or compromise the confidentiality of sensitive data. The affected products include iOS, iPadOS, macOS (Sequoia, Sonoma, and Tahoe), tvOS, visionOS, and watchOS. Successful exploitation of these vulnerabilities could have severe consequences for affected users and organizations.

## Attack Chain

1.  An attacker identifies a vulnerable Apple device running an affected operating system version.
2.  The attacker crafts a malicious payload designed to exploit one of the identified CVEs (CVE-2025-43524, CVE-2026-1837, CVE-2026-28819, CVE-2026-28840, CVE-2026-28846, CVE-2026-28847, CVE-2026-28848, CVE-2026-28870, CVE-2026-28872, CVE-2026-28873, CVE-2026-28877, CVE-2026-28878, CVE-2026-28882, CVE-2026-28883, CVE-2026-28894, CVE-2026-28897, CVE-2026-28901, CVE-2026-28902, CVE-2026-28903, CVE-2026-28904, CVE-2026-28905, CVE-2026-28906, CVE-2026-28907, CVE-2026-28908, CVE-2026-28913, CVE-2026-28914, CVE-2026-28915, CVE-2026-28917, CVE-2026-28918, CVE-2026-28919, CVE-2026-28920, CVE-2026-28922, CVE-2026-28923, CVE-2026-28924, CVE-2026-28925, CVE-2026-28929, CVE-2026-28930, CVE-2026-28936, CVE-2026-28940, CVE-2026-28941, CVE-2026-28942, CVE-2026-28943, CVE-2026-28944, CVE-2026-28946, CVE-2026-28947, CVE-2026-28950, CVE-2026-28951, CVE-2026-28952, CVE-2026-28953, CVE-2026-28954, CVE-2026-28955, CVE-2026-28956, CVE-2026-28957, CVE-2026-28958, CVE-2026-28959, CVE-2026-28961, CVE-2026-28962, CVE-2026-28963, CVE-2026-28964, CVE-2026-28965, CVE-2026-28969, CVE-2026-28971, CVE-2026-28972, CVE-2026-28974, CVE-2026-28976, CVE-2026-28977, CVE-2026-28978, CVE-2026-28983, CVE-2026-28985, CVE-2026-28986, CVE-2026-28987, CVE-2026-28988, CVE-2026-28990, CVE-2026-28991, CVE-2026-28992, CVE-2026-28993, CVE-2026-28994, CVE-2026-28995, CVE-2026-28996, CVE-2026-39869, CVE-2026-39870, CVE-2026-39871, CVE-2026-43652, CVE-2026-43653, CVE-2026-43654, CVE-2026-43655, CVE-2026-43656, CVE-2026-43658, CVE-2026-43659, CVE-2026-43660, CVE-2026-43661, CVE-2026-43666, CVE-2026-43668).
3.  The attacker delivers the payload to the target device. The delivery method depends on the specific vulnerability being exploited and could involve network-based attacks or local exploitation.
4.  The payload triggers the vulnerability, leading to arbitrary code execution within the context of the vulnerable process.
5.  The attacker leverages the initial code execution to escalate privileges on the system. This could involve exploiting additional vulnerabilities or leveraging misconfigurations.
6.  With elevated privileges, the attacker gains access to sensitive data, such as user credentials, personal information, or confidential business documents.
7.  The attacker may exfiltrate the stolen data to a remote server under their control.
8.  The attacker achieves their objective, which could include data theft, system compromise, or disruption of services.

## Impact

Successful exploitation of these vulnerabilities can lead to arbitrary code execution, privilege escalation, data breaches, and denial-of-service conditions on affected Apple devices. The impact can range from individual users having their personal data stolen to organizations suffering significant financial losses and reputational damage due to system compromise and data exfiltration. The number of potential victims is substantial given the widespread use of Apple products across various sectors.

## Recommendation

*   Apply the security patches provided by Apple in security bulletins 127110 through 127120 to address the vulnerabilities across all affected products immediately.
*   Monitor systems for suspicious activity related to the exploitation of the listed CVEs (CVE-2025-43524, CVE-2026-1837, CVE-2026-28819, CVE-2026-28840, CVE-2026-28846, CVE-2026-28847, CVE-2026-28848, CVE-2026-28870, CVE-2026-28872, CVE-2026-28873, CVE-2026-28877, CVE-2026-28878, CVE-2026-28882, CVE-2026-28883, CVE-2026-28894, CVE-2026-28897, CVE-2026-28901, CVE-2026-28902, CVE-2026-28903, CVE-2026-28904, CVE-2026-28905, CVE-2026-28906, CVE-2026-28907, CVE-2026-28908, CVE-2026-28913, CVE-2026-28914, CVE-2026-28915, CVE-2026-28917, CVE-2026-28918, CVE-2026-28919, CVE-2026-28920, CVE-2026-28922, CVE-2026-28923, CVE-2026-28924, CVE-2026-28925, CVE-2026-28929, CVE-2026-28930, CVE-2026-28936, CVE-2026-28940, CVE-2026-28941, CVE-2026-28942, CVE-2026-28943, CVE-2026-28944, CVE-2026-28946, CVE-2026-28947, CVE-2026-28950, CVE-2026-28951, CVE-2026-28952, CVE-2026-28953, CVE-2026-28954, CVE-2026-28955, CVE-2026-28956, CVE-2026-28957, CVE-2026-28958, CVE-2026-28959, CVE-2026-28961, CVE-2026-28962, CVE-2026-28963, CVE-2026-28964, CVE-2026-28965, CVE-2026-28969, CVE-2026-28971, CVE-2026-28972, CVE-2026-28974, CVE-2026-28976, CVE-2026-28977, CVE-2026-28978, CVE-2026-28983, CVE-2026-28985, CVE-2026-28986, CVE-2026-28987, CVE-2026-28988, CVE-2026-28990, CVE-2026-28991, CVE-2026-28992, CVE-2026-28993, CVE-2026-28994, CVE-2026-28995, CVE-2026-28996, CVE-2026-39869, CVE-2026-39870, CVE-2026-39871, CVE-2026-43652, CVE-2026-43653, CVE-2026-43654, CVE-2026-43655, CVE-2026-43656, CVE-2026-43658, CVE-2026-43659, CVE-2026-43660, CVE-2026-43661, CVE-2026-43666, CVE-2026-43668).
*   Implement network segmentation to limit the potential impact of a successful exploit.
