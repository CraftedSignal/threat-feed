---
title: PhpSpreadsheet CPU Denial of Service via Unbounded Row Number
slug: 2024-01-03-phpspreadsheet-dos
description: A vulnerability in PhpSpreadsheet exists where a crafted XLSX file containing a large row number can cause excessive CPU consumption due to unbounded loop iterations, leading to a denial of service.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - denial-of-service
  - phpspreadsheet
  - xlsx
  - php
vendors:
  - phpoffice
products:
  - PhpSpreadsheet
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-7c6m-4442-2x6m
rules:
  - title: Detect PhpSpreadsheet Excessive Row Iteration
    description: Detects processes potentially exploiting PhpSpreadsheet vulnerability by iterating over an extremely high number of rows, indicating a denial of service attempt.
    platform: sigma
    severity: high
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - process_creation
      - windows
  - title: Detect PhpSpreadsheet getHighestRow() usage with very large values
    description: Detects processes using PhpSpreadsheet's getHighestRow() function and obtaining extremely large row numbers, indicative of potential DOS exploitation.
    platform: sigma
    severity: medium
    tactics:
      - availability
    techniques:
      - T1499
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A vulnerability exists in PhpSpreadsheet versions 1.x through 5.6.0 where the XLSX reader does not properly validate row numbers read from XML attributes within a spreadsheet file. Specifically, the `ColumnAndRowAttributes::readRowAttributes()` method lacks a check against the maximum allowed row number (`AddressRange::MAX_ROW = 1,048,576`). An attacker can exploit this by crafting a minimal XLSX file (approximately 1.6KB) containing a `<row r="999999999"/>` element. When processed, this inflates the `cachedHighestRow` property, causing subsequent row iteration operations to attempt nearly one billion loop cycles, thereby exhausting CPU resources and leading to a denial-of-service condition. This vulnerability can be exploited in web applications that accept user-uploaded spreadsheet files, making it a significant risk for systems using vulnerable versions of PhpSpreadsheet. The vulnerability was reported in GHSA-7c6m-4442-2x6m.

## Attack Chain

1. An attacker crafts a malicious XLSX file containing an XML `<row>` element with a large `r` attribute (e.g., `<row r="999999999"/>`).
2. The attacker uploads the malicious XLSX file to a web application or system that uses PhpSpreadsheet to process spreadsheet files.
3. The PhpSpreadsheet library, specifically the `IOFactory::createReader('Xlsx')` component, is used to read the uploaded file.
4. During the parsing process, the `ColumnAndRowAttributes::readRowAttributes()` method reads the large row number from the XML attribute.
5. The large row number is then used to update the `cachedHighestRow` property in the `Worksheet` object, effectively setting it to a very high value.
6. A subsequent operation that iterates over rows using `getRowIterator()` or retrieves the highest row using `getHighestRow()` triggers a loop that iterates up to the inflated `cachedHighestRow` value.
7. The excessive number of loop iterations consumes a significant amount of CPU resources, leading to a denial-of-service condition.
8. The application becomes unresponsive or crashes due to the CPU exhaustion.

## Impact

Successful exploitation of this vulnerability leads to a CPU denial of service. A small, 1.6KB crafted XLSX file can trigger almost one billion iterations, causing the system to become unresponsive for an extended period (estimated at ~144 seconds per file). This impacts any application using `getRowIterator()` or `getHighestRow()` methods, making the system unavailable. Applications processing the spreadsheet may also exhaust memory if they attempt to accumulate data during the iteration process. The high amplification factor (small input leading to massive CPU consumption) makes this vulnerability particularly dangerous, especially in web applications that process user-supplied spreadsheets.

## Recommendation

*   Apply the recommended fix by adding row bounds validation in `readRowAttributes()` to check if `$rowIndex` is within the acceptable range (1 to `AddressRange::MAX_ROW`). This is the primary recommendation from the source advisory.
*   Deploy the Sigma rule `Detect PhpSpreadsheet Excessive Row Iteration` to detect processes that may be attempting to process XLSX files with extremely high row numbers, indicating a potential exploitation attempt.
*   Monitor web server logs for suspicious file uploads, specifically XLSX files with unusually small sizes, which might indicate an attempt to upload a malicious file exploiting this vulnerability.
