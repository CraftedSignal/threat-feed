---
title: CVE-2026-41675 xmldom XML Node Injection Vulnerability
slug: 2026-05-xmldom-injection
description: CVE-2026-41675 is an XML node injection vulnerability in the xmldom library, potentially leading to code execution or information disclosure in applications that process XML data using the affected library.
date: "2026-05-08T07:05:58Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - xmldom
  - xml-injection
  - cve
vendors:
  - Microsoft
cves:
  - id: CVE-2026-41675
    epss: 0.00047
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-41675
rules:
  - title: Detect Suspicious XML Processing Instructions
    description: Detects XML documents containing suspicious processing instructions that may indicate an XML injection attempt, especially those abusing xmldom.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Malicious XML Uploads via Content-Type
    description: Detects potential malicious XML uploads by monitoring the Content-Type header, looking for discrepancies that may indicate an attempt to bypass security checks.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

CVE-2026-41675 describes an XML node injection vulnerability within the xmldom library. This vulnerability arises from insufficient validation during the serialization of processing instructions, potentially allowing attackers to inject arbitrary XML nodes. While the specific exploitation details and affected products are not fully detailed in the provided source, the nature of the vulnerability suggests that applications using vulnerable versions of xmldom to process untrusted XML data are at risk. Successful exploitation could lead to a range of impacts, from information disclosure and denial of service to, in some contexts, remote code execution, depending on how the XML data is processed by the application.

## Attack Chain

Given the limited information in the source, this attack chain is based on common XML injection attack vectors.

1. An attacker crafts a malicious XML document containing a specially formatted processing instruction.
2. The attacker submits the malicious XML document to a vulnerable application. This could occur through a file upload, API endpoint, or other data ingestion method.
3. The vulnerable application parses the XML document using the xmldom library.
4. During the serialization of a processing instruction, the xmldom library fails to properly sanitize or escape the instruction's content.
5. The attacker-controlled content is injected into the XML structure as a new node or attribute.
6. The application processes the modified XML structure.
7. If the injected content contains executable code or commands (e.g., through XSLT transformation or other dynamic processing), it is executed within the context of the application.
8. The attacker gains control of the application or extracts sensitive information, depending on the specific injected content and the application's functionality.

## Impact

Successful exploitation of CVE-2026-41675 could allow an attacker to inject malicious XML nodes into an application's data stream. Depending on the application's functionality and the injected content, this could lead to information disclosure, denial-of-service, or potentially remote code execution. The lack of specific victim data in the source prevents quantification of the impact.

## Recommendation

*   Identify applications within your environment that utilize the `xmldom` library and determine the version in use.
*   Monitor web application logs for suspicious XML payloads, particularly those with unusual or malformed processing instructions, to detect potential exploitation attempts targeting CVE-2026-41675.  Implement the `Detect Suspicious XML Processing Instructions` Sigma rule.
*   Implement robust input validation and sanitization measures for all XML data processed by applications to prevent XML injection attacks, mitigating the risk of CVE-2026-41675.
*   Apply any available patches or updates for the `xmldom` library to address CVE-2026-41675.
