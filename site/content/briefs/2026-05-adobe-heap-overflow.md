---
title: Adobe Acrobat and Reader Heap-Based Buffer Overflow Vulnerability (CVE-2009-3459)
slug: 2026-05-adobe-heap-overflow
description: Adobe Acrobat and Reader contain a heap-based buffer overflow vulnerability, tracked as CVE-2009-3459, that could allow remote attackers to execute arbitrary code via a crafted PDF file.
date: "2026-05-20T17:31:49Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:adobe:acrobat:*:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:3.0:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:3.1:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:4.0:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:4.0.5:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:4.0.5a:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:4.0.5c:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:5.0:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:5.0.5:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:5.0.6:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:5.0.10:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:6.0:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:6.0.1:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:6.0.2:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:6.0.3:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:6.0.4:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:6.0.5:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:7.0:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:7.0.1:*:*:*:*:*:*:*
  - cpe:2.3:a:adobe:acrobat:7.0.2:*:*:*:*:*:*:*
tags:
  - cve-2009-3459
  - adobe
  - heap overflow
  - remote code execution
vendors:
  - Adobe
products:
  - Acrobat
  - Reader
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
cves:
  - id: CVE-2009-3459
    epss: 0.87025
references:
  - https://www.cve.org/CVERecord?id=CVE-2009-3459
  - https://www.cisa.gov/news-events/alerts/2009/10/13/adobe-reader-and-acrobat-vulnerabilities
  - https://web.archive.org/web/20120324170253/http://www.adobe.com/support/security/bulletins/apsb09-15.html#:~:text=CVE%2D2009%2D3459).-,NOTE%3A,-There%20are%20reports
  - https://nvd.nist.gov/vuln/detail/CVE-2009-3459
rules:
  - title: Detects CVE-2009-3459 Exploitation - Suspicious PDF File Execution
    description: Detects CVE-2009-3459 exploitation - Suspicious execution of processes spawned by Adobe Acrobat or Reader related processes, potentially indicating code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detects CVE-2009-3459 Exploitation - PDF Reader Launching Unusual Network Connection
    description: Detects CVE-2009-3459 exploitation - Adobe Acrobat or Reader process initiating network connections to unusual ports or IPs after opening a PDF.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

CVE-2009-3459 is a heap-based buffer overflow vulnerability affecting Adobe Acrobat and Reader. Successful exploitation of this vulnerability could allow a remote attacker to execute arbitrary code on a vulnerable system. The vulnerability stems from improper handling of crafted PDF files, leading to memory corruption during processing. Adobe has released security updates to address this issue. CISA has included this vulnerability in its Known Exploited Vulnerabilities catalog, emphasizing the need for organizations to apply mitigations, follow BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable by the due date of 2026-06-03. This vulnerability was initially disclosed in 2009.

## Attack Chain

1.  Attacker crafts a malicious PDF file specifically designed to trigger the heap-based buffer overflow vulnerability in Adobe Acrobat or Reader.
2.  The attacker distributes the crafted PDF file to potential victims via email, malicious websites, or other social engineering techniques.
3.  The victim opens the malicious PDF file using a vulnerable version of Adobe Acrobat or Reader.
4.  Upon opening the PDF, the application attempts to process the malicious content, leading to a buffer overflow in the heap.
5.  The buffer overflow corrupts adjacent memory regions, potentially overwriting critical data or function pointers.
6.  The attacker leverages the memory corruption to inject and execute arbitrary code within the context of the Adobe Acrobat or Reader process.
7.  The attacker's code gains control of the system, enabling them to perform malicious actions such as installing malware, stealing sensitive data, or establishing a remote backdoor.

## Impact

Successful exploitation of CVE-2009-3459 allows remote attackers to execute arbitrary code on affected systems. While the specific number of victims is unknown, the wide usage of Adobe Acrobat and Reader suggests a broad potential impact. This can lead to complete system compromise, data theft, and further propagation of malware within an organization. Failure to apply mitigations by the due date of 2026-06-03 leaves systems vulnerable to exploitation.

## Recommendation

*   Apply mitigations per vendor instructions for Adobe Acrobat and Reader to address CVE-2009-3459.
*   Follow applicable BOD 22-01 guidance for cloud services if using Adobe Acrobat or Reader in a cloud environment.
*   Discontinue use of vulnerable versions of Adobe Acrobat and Reader if mitigations are unavailable.
*   Deploy the following Sigma rules to detect potential exploitation attempts involving malicious PDF files.
