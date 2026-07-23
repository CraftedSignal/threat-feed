---
title: Bold Reports Standalone Report Designer Path Traversal to RCE Vulnerability
slug: 2026-07-bold-reports-path-traversal-rce
description: A missing filepath validation vulnerability (CVE-2026-65690) in Bold Reports Standalone Report Designer before version 14.1.12 allows authenticated attackers to perform path traversal via crafted filenames during file upload, leading to arbitrary command execution with high privileges.
date: "2026-07-23T14:22:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - path-traversal
  - rce
  - web-application
vendors:
  - Bold Reports
products:
  - Standalone Report Designer (before 14.1.12)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can exploit this path traversal weakness to execute arbitrary commands with high privileges on the server.
    confidence_band: high
cves:
  - id: CVE-2026-65690
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-65690
  - https://www.boldreports.com/resources/release-history/standalone-report-designer/14-1#14-1-12
  - https://www.vulncheck.com/advisories/bold-reports-standalone-report-designer-path-traversal-rce-via-file-upload
iocs:
  - type: url
    value: https://www.boldreports.com/resources/release-history/standalone-report-designer/14-1#14-1-12
  - type: url
    value: https://www.vulncheck.com/advisories/bold-reports-standalone-report-designer-path-traversal-rce-via-file-upload
ioc_counts:
  url: 2
rules:
  - title: Detects CVE-2026-65690 Exploitation Attempt - Bold Reports Path Traversal in File Upload
    description: Detects attempts to exploit CVE-2026-65690 by identifying path traversal sequences in URI query parameters or URI stems during web file upload requests, targeting Bold Reports Standalone Report Designer.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - webserver
rules_count: 1
---

CVE-2026-65690 identifies a critical missing filepath validation vulnerability in Bold Reports Standalone Report Designer versions prior to 14.1.12. This flaw resides within the product's file upload functionality, enabling authenticated attackers to exploit a path traversal weakness. By supplying a specially crafted filename that includes directory traversal sequences (e.g., `../`), attackers can bypass security controls and upload malicious files to arbitrary locations outside the intended upload directory. Successful exploitation can lead to arbitrary command execution with high privileges on the server, potentially compromising the integrity, confidentiality, and availability of the affected system. This vulnerability allows for a complete system takeover by an authenticated user.

## Attack Chain

1. An attacker obtains valid authentication credentials for the Bold Reports Standalone Report Designer application.
2. The authenticated attacker accesses the application's file upload functionality.
3. The attacker crafts a malicious filename containing path traversal sequences (e.g., `../../../../webshell.jsp`) and attempts to upload it.
4. Due to the missing filepath validation (CVE-2026-65690), the application fails to properly sanitize the filename.
5. The malicious file (e.g., a web shell or script) is written to an arbitrary location on the server, outside the intended upload directory.
6. The attacker then accesses the uploaded malicious file (e.g., the web shell) through a web request.
7. The web shell executes arbitrary commands with the privileges of the application, potentially leading to high-privileged system access or further compromise.

## Impact

Successful exploitation of CVE-2026-65690 grants authenticated attackers the ability to execute arbitrary commands with high privileges on the compromised server. This can lead to a complete system takeover, allowing for sensitive data exfiltration, modification, or deletion, installation of additional malware such as ransomware or backdoors, and lateral movement within the network. The integrity and confidentiality of data stored on or accessible from the server are at severe risk. The broad impact of arbitrary command execution underscores the criticality of patching this vulnerability immediately.

## Recommendation

* Patch Bold Reports Standalone Report Designer to version 14.1.12 or higher immediately to address CVE-2026-65690.
* Deploy the provided Sigma rule to your SIEM to detect attempts at path traversal through web server logs.
* Monitor web server logs for suspicious file upload activity and unusual file paths, particularly those referenced in the Sigma rule.
