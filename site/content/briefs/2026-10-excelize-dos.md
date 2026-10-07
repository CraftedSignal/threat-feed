---
title: Excelize Unbounded Column Attribute Denial of Service
slug: 2026-10-excelize-dos
description: Excelize library versions before 2.11.1 are vulnerable to a denial-of-service attack where an attacker-controlled 'max' attribute in a spreadsheet column definition forces excessive CPU and memory allocation.
date: "2026-10-07T22:53:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:xuri:excelize:*:*:*:*:*:*:*:*
vendors:
  - Excelize
products:
  - excelize (< 2.11.1-0.20260807015645-a54c578af309)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: The process is either wedged for minutes or killed by the OOM reaper.
    confidence_band: high
cves:
  - id: CVE-2026-107223
references:
  - https://github.com/advisories/GHSA-fq3v-74gv-27gm
  - https://nvd.nist.gov/vuln/detail/CVE-2026-107223
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade Excelize to 2.11.1-0.20260807015645-a54c578af309
      owner: Development
      due: 24h
      evidence: Source advisory specifies this as the fixed version
---

The Excelize Go library contains a denial-of-service (DoS) vulnerability (CVE-2026-107223) within its XML parsing logic for Excel worksheets. When the library parses an `xl/worksheets/sheetN.xml` file, it reads the `max` attribute of `<col>` elements directly into memory without validating the value against the library-defined `MaxColumns` constant (16384). 

The subsequent `flatCols()` function iterates from the minimum to the maximum column value provided in the XML, performing a deep copy and append operation for every iteration. An attacker can craft a workbook containing a `<col>` element with a large `max` attribute (e.g., 2^31-1). Upon calling column mutator functions like `SetColWidth`, `SetColStyle`, `SetColVisible`, or `SetColOutlineLevel`, the application triggers a linear growth in memory allocation and CPU usage. This leads to process exhaustion, severe latency, or OOM crashes, effectively denying service to any application processing untrusted spreadsheets. This issue affects Excelize versions from 2.1.0 prior to 2.11.1-0.20260807015645-a54c578af309.

## Attack Chain

1. Attacker crafts a malicious XLSX file containing an injected `<cols>` XML block within `xl/worksheets/sheetN.xml`.
2. The malicious block includes a `<col>` definition with a high `max` attribute, such as `<col min="1" max="2147483647" width="9"/>`.
3. The victim application receives the crafted file via a file upload or input processing stream.
4. The application calls the `OpenReader` function to load the spreadsheet into memory.
5. The application invokes a column-modifying function, such as `SetColWidth`, `SetColStyle`, or `SetColVisible`, targeting the worksheet.
6. The `flatCols()` function in the Excelize library is triggered, which executes an unbounded loop based on the attacker-supplied `max` attribute.
7. The application memory usage grows linearly with the `max` value, leading to an OOM state or CPU hang.
8. The target service becomes unresponsive, resulting in a successful denial-of-service condition.

## Impact

Successful exploitation results in service unavailability for any application relying on the Excelize library to process user-supplied spreadsheet files. The vulnerability can be exploited by an unauthenticated attacker simply by triggering a column modification on a file that passes initial opening. No specific authentication is required if the file upload path is reachable. Observed impact includes 100% CPU utilization and rapid memory exhaustion, leading to process termination.

## Recommendation

Prioritized actions for development and security teams:
- Upgrade the Excelize library to version 2.11.1-0.20260807015645-a54c578af309 or later to address CVE-2026-107223.
- Implement input validation on uploaded spreadsheet files to sanitize XML structures before passing them to document processing libraries.
- Apply resource constraints (memory and execution time limits) to background processes responsible for document parsing and mutation to mitigate potential DoS impacts from similar unpatched vulnerabilities.
