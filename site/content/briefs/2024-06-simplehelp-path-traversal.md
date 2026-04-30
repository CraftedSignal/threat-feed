---
title: SimpleHelp Path Traversal Vulnerability (CVE-2024-57728)
slug: 2024-06-simplehelp-path-traversal
description: CVE-2024-57728 is a path traversal vulnerability in SimpleHelp that allows admin users to upload arbitrary files anywhere on the file system by uploading a crafted zip file, potentially leading to arbitrary code execution.
date: "2024-06-25T10:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2024-57728
  - path-traversal
  - zip-slip
vendors:
  - SimpleHelp
products:
  - SimpleHelp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
cves:
  - id: CVE-2024-57728
    cvss: 7.2
    epss: 0.59327
references:
  - https://www.cve.org/CVERecord?id=CVE-2024-57728
  - https://simple-help.com/kb---security-vulnerabilities-01-2025#security-vulnerabilities-in-simplehelp-5-5-7-and-earlier
  - https://nvd.nist.gov/vuln/detail/CVE-2024-57728
rules:
  - title: Detect SimpleHelp Path Traversal ZIP Upload
    description: Detects ZIP archive uploads to a SimpleHelp server containing path traversal sequences in filenames, indicative of a potential Zip Slip attack.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1068
      - T1566
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious Process Creation from SimpleHelp Server User
    description: Detects processes spawned by the SimpleHelp server user which may indicate code execution from CVE-2024-57728.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

A path traversal vulnerability exists within SimpleHelp, identified as CVE-2024-57728. This flaw enables authenticated administrators to upload arbitrary files to any location on the server's file system. This is achieved through the use of a specially crafted ZIP archive (a technique known as Zip Slip). Successful exploitation allows an attacker to execute arbitrary code within the security context of the SimpleHelp server user. The vulnerability impacts SimpleHelp versions 5.5.7 and earlier. Defenders should apply vendor-provided mitigations or discontinue use of the software.

## Attack Chain

1. An attacker gains administrative access to the SimpleHelp console, either through compromised credentials or exploiting a separate authentication bypass.
2. The attacker crafts a malicious ZIP archive containing a file with a path traversal sequence (e.g., "../../ malicious.exe") in its filename.
3. The attacker uploads the crafted ZIP archive to the SimpleHelp server through a file upload functionality available to administrators.
4. The SimpleHelp server extracts the contents of the ZIP archive without proper validation of the file paths.
5. The file with the path traversal sequence is extracted to an arbitrary location on the file system outside of the intended upload directory.
6. The attacker leverages a method to execute the uploaded malicious executable. This could involve overwriting an existing system utility or service executable.
7. The malicious executable runs with the privileges of the SimpleHelp server user.
8. The attacker achieves arbitrary code execution on the host, potentially leading to complete system compromise, data exfiltration, or deployment of ransomware.

## Impact

Successful exploitation of CVE-2024-57728 allows an attacker to execute arbitrary code on the SimpleHelp server with the privileges of the SimpleHelp service account. This can result in a full compromise of the SimpleHelp server, potentially leading to data theft, service disruption, or further lateral movement within the network. The vulnerability affects SimpleHelp installations, and the impact is high due to the potential for complete system takeover.

## Recommendation

*   Apply the mitigations provided by SimpleHelp to patch the vulnerability. Refer to the vendor advisory for instructions: https://simple-help.com/kb---security-vulnerabilities-01-2025#security-vulnerabilities-in-simplehelp-5-5-7-and-earlier
*   Monitor SimpleHelp server file uploads for ZIP archives containing path traversal sequences (e.g., "../") in filenames using a file integrity monitoring system (FIM) or endpoint detection and response (EDR) solution. Deploy the "Detect SimpleHelp Path Traversal ZIP Upload" Sigma rule to identify suspicious ZIP files.
*   Implement strict access controls and regularly audit administrative access to the SimpleHelp console to prevent unauthorized users from exploiting the vulnerability.
