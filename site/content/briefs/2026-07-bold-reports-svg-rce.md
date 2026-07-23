---
title: Bold Reports Standalone Report Designer Path Traversal Vulnerability (CVE-2026-65687)
slug: 2026-07-bold-reports-svg-rce
description: CVE-2026-65687 describes a path traversal vulnerability in Bold Reports Standalone Report Designer prior to version 14.1.12, allowing an unauthenticated attacker to read arbitrary files from the server filesystem by exploiting a missing filepath validation flaw in the SVG processing feature, potentially leading to full unauthorized access via disclosure of sensitive server files like authentication credentials.
date: "2026-07-23T14:19:51Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - path-traversal
  - arbitrary-file-read
  - web-vulnerability
  - critical-vulnerability
vendors:
  - SyncFusion
products:
  - Bold Reports Standalone Report Designer
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: read arbitrary files from the server filesystem
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: disclose sensitive server files, including authentication credentials
    confidence_band: high
cves:
  - id: CVE-2026-65687
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65687
  - https://www.boldreports.com/resources/release-history/standalone-report-designer/14-1#14-1-12
  - https://www.vulncheck.com/advisories/bold-reports-standalone-report-designer-arbitrary-file-read-via-svg-processing
rules:
  - title: Detects CVE-2026-65687 Exploitation - Bold Reports SVG Path Traversal
    description: Detects CVE-2026-65687 exploitation - HTTP requests containing path traversal sequences in the URI or query parameters, indicating an attempt to read arbitrary files via the Bold Reports Standalone Report Designer's SVG processing feature.
    platform: sigma
    severity: high
    tactics:
      - collection
      - initial_access
    techniques:
      - T1005
      - T1190
    data_sources:
      - webserver
rules_count: 1
---

A critical path traversal vulnerability, tracked as CVE-2026-65687, affects Bold Reports Standalone Report Designer versions prior to 14.1.12. This flaw resides within the SVG processing feature, where a missing filepath validation allows unauthenticated attackers to read arbitrary files directly from the server's filesystem. By crafting and sending a malicious HTTP request, adversaries can exploit this weakness to disclose sensitive server files, including critical configuration data and authentication credentials. Successful exploitation could grant attackers full unauthorized access to the application and potentially the underlying system, posing a severe risk to data integrity and confidentiality. The vulnerability has been assigned a CVSS v3.1 base score of 9.8, indicating its critical severity and ease of exploitation.

## Attack Chain

1. **Discovery:** An unauthenticated attacker identifies an internet-facing instance of Bold Reports Standalone Report Designer through reconnaissance or network scanning.
2. **Vulnerability Identification:** The attacker determines the specific version of the application is vulnerable to CVE-2026-65687, either by direct version disclosure or by probing for the SVG processing functionality.
3. **Payload Crafting:** The attacker creates a specially crafted HTTP request, designed to exploit the SVG processing feature, embedding path traversal sequences (e.g., `../../../../`) within the SVG content or associated request parameters.
4. **Exploitation Attempt:** The malicious request, containing the path traversal payload targeting sensitive system files (e.g., `/etc/passwd`, `/Windows/System32/config/SAM`), is sent to the vulnerable Bold Reports application.
5. **Arbitrary File Read:** Due to the application's failure to properly validate file paths during SVG processing, the server attempts to access and read the file specified by the attacker's path traversal sequence.
6. **Sensitive Data Exfiltration:** The content of the targeted arbitrary file is read by the application and subsequently included in the HTTP response returned to the attacker.
7. **Post-Exploitation:** The attacker analyzes the exfiltrated file content, extracting sensitive information such as application configuration details, user credentials, or system hashes, to further escalate privileges or gain complete unauthorized control over the application or host.

## Impact

The successful exploitation of CVE-2026-65687 allows unauthenticated attackers to read any file on the server's filesystem where the Bold Reports Standalone Report Designer is hosted. This direct file access can lead to the disclosure of highly sensitive information, including critical configuration files, user authentication credentials, and system-specific data. Attackers can leverage this information to achieve full unauthorized access to the application, escalate privileges, compromise user accounts, or gain access to other networked resources, potentially leading to data breaches, system compromise, and significant operational disruption. The vulnerability has a critical CVSS v3.1 score of 9.8, reflecting its severe potential for harm.

## Recommendation

* Patch CVE-2026-65687 immediately by updating Bold Reports Standalone Report Designer to version 14.1.12 or later, as indicated in the Bold Reports release history reference.
* Deploy the Sigma rule "Detects CVE-2026-65687 Exploitation - Bold Reports SVG Path Traversal" to your SIEM to monitor for exploitation attempts of this vulnerability.
* Monitor web server logs for suspicious HTTP requests containing path traversal sequences, especially those targeting application endpoints related to SVG processing or file handling.
