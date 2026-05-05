---
title: ERPGo SaaS 3.9 CSV Injection Vulnerability
slug: 2026-05-erpgo-csv-injection
description: ERPGo SaaS version 3.9 is vulnerable to CSV injection, allowing authenticated attackers to execute arbitrary code by injecting malicious formulas into the vendor name field during vendor creation, which are then executed when the exported CSV file is opened in a spreadsheet application.
date: "2026-05-05T12:16:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - csv-injection
  - code-execution
  - web-application
vendors:
  - ERPGo
products:
  - ERPGo SaaS 3.9
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1205
    technique_name: Traffic Signaling
cves:
  - id: CVE-2023-54348
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-54348
  - https://codecanyon.net/item/erpgo-saas-all-in-one-business-erp-with-project-account-hrm-crm-pos/33263426
  - https://rajodiya.com/
  - https://www.exploit-db.com/exploits/51220
  - https://www.vulncheck.com/advisories/erpgo-saas-csv-injection-via-vendor-creation
rules:
  - title: Detect CSV Injection via Formula in Process Creation
    description: Detects potential CSV injection exploitation attempts by monitoring for process creation events with suspicious command lines indicative of formula execution within spreadsheet applications.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect CSV Injection via Formula in File Content
    description: Detects CSV files containing potentially malicious formulas that could trigger code execution when opened in spreadsheet applications.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1204.002
    data_sources:
      - file_event
      - windows
rules_count: 2
---

ERPGo SaaS 3.9 is susceptible to a CSV injection vulnerability that allows authenticated attackers to inject arbitrary code. The vulnerability stems from the insufficient sanitization of input provided in the vendor name field during vendor creation. By injecting malicious formulas, such as `=10+20+cmd|' /C calc'!A0`, attackers can achieve arbitrary code execution when a user opens the exported CSV file in a spreadsheet application. This vulnerability poses a significant risk to organizations using ERPGo SaaS 3.9, as it could lead to unauthorized access, data compromise, and further exploitation of the system. The vulnerability was reported on May 5, 2026.

## Attack Chain

1. An attacker authenticates to the ERPGo SaaS 3.9 application.
2. The attacker navigates to the vendor creation form.
3. In the "vendor name" field, the attacker injects a malicious CSV formula, such as `=10+20+cmd|' /C calc'!A0`.
4. The attacker submits the form, creating a new vendor entry with the malicious payload.
5. An authorized user exports vendor data to a CSV file.
6. The user opens the exported CSV file using a spreadsheet application like Microsoft Excel or LibreOffice Calc.
7. The spreadsheet application interprets and executes the injected formula.
8. The attacker achieves arbitrary code execution on the user's system, potentially leading to further compromise.

## Impact

Successful exploitation of this CSV injection vulnerability allows an attacker to execute arbitrary code on the system of the user opening the exported CSV file. This could lead to the installation of malware, data exfiltration, or further compromise of the internal network. Given the widespread use of spreadsheet applications, a single successful injection could affect multiple users and systems. The potential for data compromise and system takeover makes this a high-severity vulnerability.

## Recommendation

*   Deploy the Sigma rule `Detect CSV Injection via Formula in Process Creation` to your SIEM to identify potential exploitation attempts based on spawned processes (process_creation logs).
*   Deploy the Sigma rule `Detect CSV Injection via Formula in File Content` to your SIEM to identify potentially crafted CSV files based on file content analysis (file_event logs).
*   Upgrade to a patched version of ERPGo SaaS that addresses this vulnerability; consult the vendor's security advisories for updates.
*   Educate users about the risks of opening CSV files from untrusted sources and the potential for CSV injection attacks.
