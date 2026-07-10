---
title: Autodesk Fusion Stored XSS Vulnerability via Maliciously Crafted Design Name
slug: 2026-04-autodesk-fusion-xss
description: A stored cross-site scripting (XSS) vulnerability exists in the Autodesk Fusion desktop application, where a maliciously crafted HTML payload stored in a design name and exported to CSV can be triggered, potentially leading to local file reads or arbitrary code execution.
date: "2024-02-29T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xss
  - autodesk
  - cve-2026-4345
  - application
vendors:
  - Autodesk
products:
  - Autodesk Fusion
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-4345
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-4345
iocs:
  - type: email
    value: '[email&#160;protected]'
  - type: email
    value: '[email&#160;protected]'
ioc_counts:
  email: 2
rules:
  - title: Detect CSV File Executing Commands
    description: Detects potential command execution originating from CSV files opened in applications like Excel.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - process_creation
      - windows
  - title: Detect Suspicious CSV Export with Script Tags
    description: Detects the creation of CSV files containing potential script tags, indicative of XSS attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1566.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

A stored cross-site scripting (XSS) vulnerability, identified as CVE-2026-4345, affects the Autodesk Fusion desktop application. The vulnerability arises from the application's handling of design names. Specifically, a malicious actor can inject a crafted HTML payload into a design name. When this design name is exported to a CSV file, the payload is triggered. Successful exploitation of this vulnerability could enable an attacker to read local files or execute arbitrary code within the context of the current user's process. This can lead to a compromise of confidentiality and integrity. The vulnerability poses a risk to users who routinely export design data to CSV format.

## Attack Chain

1.  The attacker crafts a malicious HTML payload designed to execute arbitrary JavaScript code.
2.  The attacker opens an Autodesk Fusion design and renames it using the crafted HTML payload as the new design name.
3.  The malicious design name is saved within the Autodesk Fusion project file.
4.  The user exports the designs within Autodesk Fusion, including the renamed design, into a CSV file.
5.  The CSV file is opened by a user with a program that renders HTML, such as Microsoft Excel or a web browser.
6.  The crafted HTML payload within the design name is executed as the application renders the CSV file, triggering the XSS vulnerability.
7.  The attacker gains the ability to execute arbitrary code in the context of the application.
8.  The attacker leverages the executed code to read local files or execute commands on the system.

## Impact

Successful exploitation of the stored XSS vulnerability (CVE-2026-4345) in Autodesk Fusion allows an attacker to execute arbitrary code within the application context. This could lead to the theft of sensitive information by reading local files, or further compromise of the system through arbitrary code execution. While the specific number of affected users is not available, the vulnerability's presence in a widely used application like Autodesk Fusion means a successful exploit could have a significant impact across various engineering and design sectors.

## Recommendation

*   Monitor process creations for instances of applications like Microsoft Excel or web browsers executing commands from unusual locations that may indicate CSV files containing malicious payloads (see Sigma rule: "Detect CSV File Executing Commands").
*   Implement input validation and sanitization measures for design names to prevent the injection of HTML or other potentially harmful code within Autodesk Fusion.
*   Educate users about the risks of opening CSV files from untrusted sources and the potential for embedded malicious content.
*   Monitor for file creations related to CSV exports, particularly those containing suspicious script tags or encoded commands (see Sigma rule: "Detect Suspicious CSV Export with Script Tags").
*   Apply future patches released by Autodesk to address CVE-2026-4345 as soon as they become available.
