---
title: Excelize Unbounded Row Index Allocation Denial-of-Service Vulnerability
slug: 2026-07-excelize-dos
description: An unbounded row index allocation vulnerability (CWE-770) exists in the `checkSheet()` function of the `github.com/xuri/excelize/v2` library, allowing an unauthenticated attacker to craft a malicious XLSX file with a specially crafted row index value that triggers an out-of-memory error or runtime panic, leading to a denial-of-service condition in Go applications processing untrusted spreadsheets.
date: "2026-07-10T19:29:53Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
  - golang
  - xlsx
  - library
  - cwe-770
vendors:
  - xuri
products:
  - excelize v2
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Application Layer Protocol Denial of Service
    evidence: An unauthenticated remote attacker can crash or memory-exhaust any Go application that uses `github.com/xuri/excelize/v2` to open attacker-supplied XLSX files and subsequently calls any cell-reading API... The attack requires no authentication and no user interaction beyond uploading a malicious file.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-h69g-9hx6-f3v4
---

An unauthenticated attacker can exploit a denial-of-service vulnerability (CWE-770) in the `github.com/xuri/excelize/v2` Go library, affecting versions up to the fix. The vulnerability arises from unbounded row index allocation within the `checkSheet()` function, which fails to validate the attacker-controlled `<row r="N">` XML attribute value in a malicious XLSX file. By crafting an XLSX file with an extremely large (e.g., 2147483647) or negative (e.g., -1) row index, attackers can trigger either a critical out-of-memory condition, leading to a process kill, or a runtime panic due to an out-of-bounds slice index. This impacts any Go application that uses the `excelize/v2` library to process untrusted XLSX documents, such as web services with upload endpoints or CLI tools, enabling trivial, unauthenticated service disruption with a small payload.

## Attack Chain

1. An attacker crafts a malicious XLSX file, embedding an excessively large (e.g., `r="2147483647"`) or negative (e.g., `r="-1"`) value in the `<row r="...">` XML attribute within `xl/worksheets/sheet1.xml`.
2. A legitimate Go application opens this malicious XLSX file using the `excelize.OpenFile()` function.
3. The application then attempts to read cell values by calling `GetCellValue()` or any other API that internally invokes `workSheetReader`.
4. The `workSheetReader` component decodes the worksheet XML, deserializing the attacker-controlled `r` attribute value into an integer without any initial bounds validation.
5. The `checkSheet()` function processes the sheet data, encountering the invalid `r` value.
6. Within `checkSheet()`, the library attempts to allocate a slice using `make([]xlsxRow, row)` where `row` is the attacker-controlled large or negative value.
7. If `row` is excessively large (e.g., 2147483647), this triggers an attempt to allocate approximately 16 GB of memory, leading to an out-of-memory (OOM) error and process termination.
8. If `row` is negative (e.g., -1), subsequent operations on the `sheetData.Row` slice result in an `index out of range` runtime panic, crashing the application.
9. The Go application terminates abnormally, resulting in a denial-of-service condition for users.

## Impact

This is a critical Denial-of-Service vulnerability. An unauthenticated remote attacker can trivially crash or memory-exhaust any Go application that utilizes the `github.com/xuri/excelize/v2` library to open untrusted XLSX files and subsequently calls cell-reading APIs like `GetCellValue`. Affected systems include web services with spreadsheet upload or import functionality, data processing pipelines, and CLI tools that parse user-supplied spreadsheets. The attack requires no authentication and minimal user interaction (e.g., uploading the malicious file). The payload is a compact, few-hundred-byte XLSX file, making it easy to deliver. Repeated or concurrent exploitation can severely disrupt or completely deny service to all users of the vulnerable application.

## Recommendation

* Upgrade `github.com/xuri/excelize/v2` to a patched version immediately to remediate the unbounded row index allocation vulnerability.
* Implement robust resource limits for any application processing untrusted files to mitigate the impact of potential memory exhaustion attacks.
* Monitor application logs for `fatal error: runtime: out of memory` messages or `panic: runtime error: index out of range` messages originating from the `excelize` library to detect attempted or successful exploitation.
