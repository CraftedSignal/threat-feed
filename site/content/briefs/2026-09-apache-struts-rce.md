---
title: Critical RCE Vulnerability in Apache Struts (S2-067)
slug: 2026-09-apache-struts-rce
description: A critical remote code execution vulnerability (CVE-2024-53677) in Apache Struts versions 2.0.0 through 6.3.0.2 allows attackers to leverage path traversal during file uploads to execute arbitrary code.
date: "2026-09-15T10:28:25Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:apache:struts:*:*:*:*:*:*:*:*
tags:
  - apache-struts
  - rce
  - file-upload
  - web-application-attack
vendors:
  - Apache
products:
  - Struts (2.0.0-6.3.0.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability exists within the FileUploadInterceptor component, allowing attackers to leverage path traversal during file uploads to place malicious files on the server and achieve arbitrary code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An unauthenticated attacker can manipulate file upload parameters to perform path traversal, enabling them to upload arbitrary files to locations outside of the intended directory.
    confidence_band: high
cves:
  - id: CVE-2024-53677
    cvss: 9.8
    epss: 0.78198
references:
  - https://cwiki.apache.org/confluence/display/WW/S2-067
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-TAM-K592-CVE-2024-53677-S2-067
rules:
  - title: Detects CVE-2024-53677 Exploitation - Path Traversal in Struts File Upload
    description: Detects potential path traversal exploitation attempts targeting Apache Struts file upload functionality
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade all instances of Apache Struts to 6.4.0 or later
      owner: IT Operations
      due: 24h
      evidence: Apache Struts official advisory S2-067 recommends upgrading to 6.4.0.
  mitigation_plan:
    - priority: immediate
      action: Transition to the new File Upload Mechanism in Struts 6.4.0
      owner: IT Operations
      addresses: CVE-2024-53677
      evidence: The vulnerability requires refactoring as the fix is not backward compatible.
---

Apache Struts versions 2.0.0 through 6.3.0.2 are vulnerable to a remote code execution (RCE) flaw, tracked as CVE-2024-53677 (also identified as S2-067). The vulnerability resides in the framework's file upload logic, specifically within the FileUploadInterceptor component. An unauthenticated attacker can manipulate file upload parameters to perform path traversal, enabling them to upload arbitrary files to locations outside of the intended directory. By placing executable files, such as .jsp scripts, into web-accessible directories, an attacker can achieve remote code execution. Because this vulnerability involves a significant change to the file upload mechanism, the vendor notes that the fix in version 6.4.0 is not backward compatible, requiring organizations to refactor existing Action classes. The CVSS 9.8 rating reflects the ease of exploitation, as it requires no privileges or user interaction.

## Attack Chain

1. Attacker identifies an internet-facing application utilizing a vulnerable version of the Apache Struts framework.
2. Attacker crafts a malicious HTTP POST request targeting the /upload.action endpoint.
3. Attacker injects path traversal sequences (e.g., ../) into the filename parameter of the multipart/form-data request body.
4. The FileUploadInterceptor fails to sanitize the input, allowing the attacker to traverse the filesystem directory structure.
5. The server writes the attacker-supplied malicious file (e.g., a webshell) to an arbitrary, attacker-controlled location within the web root.
6. Attacker sends a secondary HTTP GET request to the path of the newly uploaded file to trigger script execution.
7. The application server executes the malicious script, granting the attacker arbitrary code execution on the underlying host.

## Impact

Successful exploitation allows for full system compromise, including unauthorized access to sensitive data, potential lateral movement within the network, and complete control over the affected application server. This vulnerability affects all organizations utilizing Apache Struts within the specified version range (2.0.0-6.3.0.2).

## Recommendation

1. Upgrade all Apache Struts deployments to version 6.4.0 or later immediately to patch CVE-2024-53677.
2. Audit web server logs for suspicious POST requests targeting "/upload.action" that contain path traversal sequences (e.g., "..", "%2e%2e") in the filename or form parameters.
3. Perform code refactoring as necessary to support the new file upload mechanism introduced in version 6.4.0, as it is not backward compatible with previous implementations.
4. Implement Web Application Firewall (WAF) rules to inspect multipart form data for traversal characters in the filename field.
