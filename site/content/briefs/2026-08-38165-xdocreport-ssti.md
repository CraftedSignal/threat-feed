---
title: Critical RCE via Server-Side Template Injection in OpenSAGRES XDocReport
slug: 2026-08-38165-xdocreport-ssti
description: OpenSAGRES XDocReport is vulnerable to a critical server-side template injection (SSTI) flaw via the Apache Velocity engine, allowing unauthenticated remote code execution through malicious .docx uploads.
date: "2026-08-29T17:47:04Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - rce
  - ssti
  - webserver
vendors:
  - OpenSAGRES
  - Apache
products:
  - XDocReport
  - Velocity
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: This vulnerability allows attackers to upload specially crafted .docx documents to an application using XDocReport to trigger arbitrary code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: An attacker can craft a malicious .docx document containing Velocity template expressions and upload it to an application that utilizes XDocReport.
    confidence_band: high
cves:
  - id: CVE-2026-38165
    cvss: 9.8
    epss: 0.00596
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AT190510-CUONG-CVE-2026-38165-SSTI-
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all applications using XDocReport
      owner: IT Operations
      due: 24h
      evidence: Source confirms XDocReport is the vulnerable component.
  mitigation_plan:
    - priority: immediate
      action: Restrict file uploads and implement input filtering
      owner: IT Operations
      addresses: CVE-2026-38165
      evidence: SSTI vulnerability results from lack of input filtering.
---

OpenSAGRES XDocReport contains a critical server-side template injection (SSTI) vulnerability, tracked as CVE-2026-38165, affecting the Apache Velocity engine integration. The flaw exists because the application fails to perform adequate input validation or filtering when rendering content from uploaded .docx files. An attacker can craft a malicious .docx document containing Velocity template expressions and upload it to an application that utilizes XDocReport for document processing. When the server processes the document, the malicious expressions are executed, leading to remote code execution (RCE) with the privileges of the web application service. This vulnerability poses a severe risk to any organization that accepts user-provided .docx files for server-side template processing, potentially resulting in full system compromise, sensitive data exfiltration, and unauthorized access to backend resources.

## Attack Chain

1. The attacker identifies an application that utilizes OpenSAGRES XDocReport for processing or rendering .docx files.
2. The attacker crafts a malicious .docx document that incorporates Apache Velocity template syntax designed to execute system commands.
3. The attacker navigates to the target application's file upload interface.
4. The attacker uploads the weaponized .docx file to the application.
5. The application triggers the XDocReport process to handle the document rendering.
6. The Apache Velocity engine parses the embedded malicious template expressions without sanitization.
7. The engine executes the injected expressions in the context of the server-side process, achieving remote code execution.

## Impact

Successful exploitation of CVE-2026-38165 allows for unauthenticated remote code execution on the target server. This enables attackers to steal sensitive information, execute illegal system commands, modify or delete critical application files, and potentially gain full control over the host infrastructure. The vulnerability is rated with a CVSS score of 9.8, reflecting its high potential for total system compromise in affected environments.

## Recommendation

1. Identify all internal and external-facing applications utilizing the OpenSAGRES XDocReport library.
2. Implement strict file upload validation policies that reject files containing suspicious template syntax or perform sandboxed processing of user-supplied documents.
3. Monitor web server access logs for anomalous POST requests to document upload endpoints, specifically looking for payloads containing typical Velocity or Java-related keywords.
4. Coordinate with vendors and developers to ensure the XDocReport library is updated to the latest secure version once a patch becomes available.
5. Review application service account permissions to ensure the principle of least privilege is applied, minimizing the potential impact of a successful RCE.
