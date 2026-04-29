---
title: PhpSpreadsheet XML Reader Denial of Service via Unbounded Row Index
slug: 2024-01-09-phpspreadsheet-dos
description: PhpSpreadsheet is vulnerable to a denial-of-service attack by crafting a SpreadsheetML XML file with an excessively large row index, which exhausts server CPU resources due to unbounded iteration.
date: "2024-01-09T18:45:00Z"
type: coverage
types:
  - coverage
severities:
  - medium
tags:
  - denial-of-service
  - xml
  - phpspreadsheet
vendors:
  - phpoffice
products:
  - PhpSpreadsheet
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
references:
  - https://github.com/advisories/GHSA-84wq-86v6-x5j6
rules:
  - title: Detect Suspicious PhpSpreadsheet XML Row Index
    description: Detects SpreadsheetML XML files with abnormally large row indexes, potentially indicating a denial-of-service attack attempt.
    platform: sigma
    severity: high
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - webserver
      - linux
  - title: Detect PhpSpreadsheet High CPU Usage
    description: Detects high CPU usage by the PHP process associated with PhpSpreadsheet XML processing, which can indicate a denial-of-service attempt.
    platform: sigma
    severity: medium
    tactics:
      - resource_development
    techniques:
      - T1588.006
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

The PhpSpreadsheet library is susceptible to a denial-of-service (DoS) vulnerability within its SpreadsheetML XML reader (`Reader\Xml`). This flaw arises because the reader fails to validate the `ss:Index` row attribute against the maximum allowed row count (`AddressRange::MAX_ROW = 1,048,576`). By crafting a malicious SpreadsheetML XML file containing an extremely large `ss:Index` value (e.g., "999999999") on a `<Row>` element, an attacker can inflate the internal `cachedHighestRow` property to approximately 1 billion. Subsequently, any call to `getRowIterator()` without a specified end row will attempt to iterate over this inflated range, leading to CPU exhaustion and ultimately a DoS condition. This issue affects versions of PhpSpreadsheet from 2.0.0 to 5.6.0 and poses a risk to PHP applications that process user-uploaded SpreadsheetML XML files.

## Attack Chain

1. An attacker crafts a malicious SpreadsheetML XML file (e.g., `poc.xml`).
2. The crafted XML file contains a `<Row>` element with an `ss:Index` attribute set to a very large integer (e.g., `ss:Index="999999999"`).
3. A PHP application using PhpSpreadsheet loads the malicious XML file using `IOFactory::createReader('Xml')->load('poc.xml')`.
4. The `loadSpreadsheetFromFile` method in `src/PhpSpreadsheet/Reader/Xml.php` processes the `<Row>` element, reads the `ss:Index` value, and casts it to an integer without validation.
5. The `getRowDimension()` method in `src/PhpSpreadsheet/Worksheet.php` is called with the attacker-controlled `$rowID`, inflating the `cachedHighestRow` property.
6. A subsequent call to `$sheet->getRowIterator()` attempts to iterate from the beginning to the inflated `cachedHighestRow`, triggering excessive CPU consumption.
7. The server's CPU resources are exhausted, leading to a denial-of-service condition.

## Impact

The vulnerability allows attackers to cause a denial-of-service condition on servers running PHP applications that utilize PhpSpreadsheet to process SpreadsheetML XML files. The impact includes:

- CPU exhaustion with a small malicious file (~300 bytes).
- Blocking PHP worker processes, affecting concurrent users.
- Triggering PHP `max_execution_time` limits while still consuming resources.
- Applications are vulnerable without authentication if they allow the processing of uploaded SpreadsheetML files.

## Recommendation

- Implement validation for the `ss:Index` attribute in `src/PhpSpreadsheet/Reader/Xml.php` to ensure it does not exceed `AddressRange::MAX_ROW`. Apply this validation to both `<Row>` and `<Cell>` elements. Use the fix from the advisory (https://github.com/advisories/GHSA-84wq-86v6-x5j6) as a reference.
- Deploy the Sigma rule `DetectSuspiciousPhpSpreadsheetXML` to detect the use of extremely large row indexes in SpreadsheetML files.
- Monitor web server logs for requests uploading XML files and triggering high CPU usage, correlating with the execution of PhpSpreadsheet.
