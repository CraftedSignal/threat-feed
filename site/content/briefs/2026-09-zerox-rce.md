---
title: CVE-2026-85672 OS Command Injection in zerox
slug: 2026-09-zerox-rce
description: The zerox library version 1.1.20 is susceptible to OS command injection via maliciously crafted URLs that interpolate unsanitized file extensions into shell-executed poppler utility commands.
date: "2026-09-04T15:26:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:zerox:zerox:1.1.20:*:*:*:*:*:*:*
tags:
  - cve-2026-85672
  - command-injection
  - rce
  - vulnerability
vendors:
  - zerox
products:
  - zerox (1.1.20)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can craft document URLs with malicious file extensions containing command substitution syntax to execute arbitrary OS commands before document processing occurs.
    confidence_band: high
cves:
  - id: CVE-2026-85672
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85672
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Upgrade zerox to the latest patched version
      owner: IT Operations
      due: 24h
      evidence: Source identifies CVE-2026-85672 in version 1.1.20
  mitigation_plan:
    - priority: immediate
      action: Patch zerox to the latest non-vulnerable version
      owner: IT Operations
      addresses: CVE-2026-85672
      evidence: CVE-2026-85672
---

Zerox version 1.1.20 contains a critical OS command injection vulnerability within its file download mechanism. The flaw exists because the library derives temporary file extensions directly from provided document URLs without proper sanitization. These extensions are then interpolated into system shell commands that invoke poppler utilities for document processing.

An attacker can exploit this by supplying a crafted URL where the file extension portion includes shell command substitution syntax (e.g., $(command)). When the application attempts to download or process the document, the underlying shell executes the injected payload before the processing task proceeds. This allows for unauthenticated arbitrary OS command execution on the host running the zerox-dependent service. Given that this component is often used in automated document ingestion pipelines, the impact is significant, potentially leading to full system compromise or lateral movement from the processing environment.

## Impact

Successful exploitation allows for arbitrary code execution with the privileges of the application process. This impacts any server or containerized environment utilizing zerox 1.1.20 to process remote documents. Given the nature of command injection in document parsing pipelines, an attacker could potentially exfiltrate sensitive files, pivot into internal network segments, or deploy further malware.

## Recommendation

- Upgrade to a version of zerox beyond 1.1.20 that addresses this sanitization flaw.
- Audit logs for process creation events originating from the application process that invoke shell command substitutions or unexpected poppler-related binaries.
- Implement strict input validation for all URLs submitted to the document ingestion pipeline to ensure no shell metacharacters are present.
