---
title: Unrestricted File Upload Vulnerability in hcr707305003 shiroiAdmin
slug: 2026-07-shiroiadmin-unrestricted-upload
description: A remote unrestricted file upload vulnerability (CVE-2026-15488) exists in hcr707305003 shiroiAdmin versions 1.1 and 1.3, allowing attackers to upload arbitrary files by manipulating the 'File' argument in FileController::upload, potentially leading to remote code execution.
date: "2026-07-12T09:18:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - web
  - file-upload
  - remote-code-execution
vendors:
  - hcr707305003
products:
  - shiroiAdmin < 1.4
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be launched remotely. The exploit has been publicly disclosed and may be utilized.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1505
    technique_name: ""
    evidence: Executing a manipulation of the argument File can lead to unrestricted upload... potentially leading to arbitrary code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Executing a manipulation of the argument File can lead to unrestricted upload... potentially leading to arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2026-15488
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-15488
rules:
  - title: Detects CVE-2026-15488 Exploitation - Unrestricted File Upload
    description: Detects CVE-2026-15488 exploitation attempts targeting hcr707305003 shiroiAdmin by identifying suspicious POST requests to the FileController::upload endpoint with common web shell file extensions in the URI.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
      - persistence
    techniques:
      - T1059
      - T1190
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
---

A high-severity vulnerability, identified as CVE-2026-15488, has been discovered in hcr707305003 shiroiAdmin versions 1.1 and 1.3. This flaw, residing in the `FileController::upload` function located within `app/common/controller/FileController.php`, allows for unrestricted file uploads. Attackers can remotely exploit this vulnerability by manipulating the 'File' argument during an upload request, enabling them to bypass security checks and place arbitrary files, including web shells, onto the server. This can lead to remote code execution and full compromise of the affected system. A public exploit for this vulnerability exists, increasing the urgency for immediate patching. The vendor, hcr707305003, was contacted but did not respond to the disclosure.

## Attack Chain

1. Attacker identifies an internet-facing hcr707305003 shiroiAdmin 1.1 or 1.3 instance.
2. Attacker crafts an HTTP POST request targeting the `FileController::upload` function in `app/common/controller/FileController.php`.
3. The attacker manipulates the 'File' argument within the request to include a malicious file, such as a web shell (e.g., `shell.php`, `cmd.jsp`, `malware.asp`).
4. The vulnerable `FileController::upload` function processes the request without proper validation of the uploaded file's type or content.
5. The malicious file (web shell) is successfully uploaded and stored on the web server in an accessible location.
6. The attacker sends a subsequent HTTP GET or POST request to access and execute the uploaded web shell.
7. The web shell provides the attacker with arbitrary code execution capabilities on the underlying server.
8. Attacker leverages code execution for further compromise, such as data exfiltration, privilege escalation, or deploying additional malware.

## Impact

Successful exploitation of CVE-2026-15488 leads to arbitrary code execution on the server hosting hcr707305003 shiroiAdmin. This allows attackers to gain full control over the compromised system, potentially enabling them to steal sensitive data, deface websites, install additional malware, establish persistence, or pivot to other systems within the network. Since a public exploit is available, any organization utilizing affected versions of shiroiAdmin is at critical risk of immediate and severe compromise.

## Recommendation

* Patch CVE-2026-15488 immediately by upgrading hcr707305003 shiroiAdmin to version 1.4 or higher.
* Deploy the Sigma rule "Detects CVE-2026-15488 Exploitation - Unrestricted File Upload" to your SIEM and monitor web server logs for suspicious POST requests to the `FileController::upload` endpoint with malicious file extensions.
* Ensure web server logging is comprehensive, capturing HTTP method, URI stem, URI query, and response status codes.
