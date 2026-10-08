---
title: Arbitrary File Read, Write, and Execution in Docling via Tectonic Engine
slug: 2026-10-docling-tectonic-rce
description: The Docling library contains a vulnerability (CVE-2026-105744) allowing arbitrary file read/write and potential command execution when processing untrusted LaTeX input with the Tectonic engine enabled.
date: "2026-10-08T13:13:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:docling:docling:*:*:*:*:*:*:*:*
vendors:
  - docling-project
products:
  - docling (2.94.0 - 2.131.9)
  - docling-slim (2.94.0 - 2.131.9)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: If the caller also sets tikz_engine_allow_shell_escape=True, the document can run shell commands through \write18.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A crafted .tex file can read files the process can read and write files at paths the process can write.
    confidence_band: high
cves:
  - id: CVE-2026-105744
    cvss: 7.5
    epss: 0.00304
references:
  - https://github.com/advisories/GHSA-x3q2-h9hx-4r4j
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade docling and docling-slim to version 2.132.0 or later.
      owner: IT Operations
      due: 24h
      evidence: Mitigated in docling 2.132.0.
  mitigation_plan:
    - priority: immediate
      action: Disable shell escape in Docling pipeline options and sandbox document processing.
      owner: Security Engineering
      addresses: CVE-2026-105744
      evidence: Untrusted LaTeX rendered with tikz_engine="tectonic" should still be processed in an isolated environment.
---

Docling (versions 2.94.0 through 2.131.x) contains a high-severity vulnerability involving its integration with the Tectonic LaTeX engine. When users configure the `LatexBackendOptions` with `tikz_engine="tectonic"` to process documents containing TikZ diagrams, the library fails to restrict TeX's file primitives. This allows a maliciously crafted LaTeX document to perform arbitrary file reads, writes, and overwrites at locations accessible to the process.

Furthermore, if the `tikz_engine_allow_shell_escape` option is set to `True`, the vulnerability can be escalated to arbitrary command execution via the `\write18` primitive. This threat is particularly significant for applications that process user-submitted documents or automate report generation. Users are strongly advised to upgrade to Docling 2.132.0 or later, which implements input sanitization and restricts Tectonic execution flags. For environments that cannot immediately patch, Docling must be run within a hardened, isolated sandbox (e.g., containerized, read-only filesystem, no host mounts) to mitigate the impact of unauthorized file system operations.

## Attack Chain

1. The attacker creates a malicious LaTeX document incorporating TikZ diagrams containing TeX primitives such as `\openin`, `\openout`, or `\write18`.
2. The attacker submits this document to an application or service that utilizes the Docling library for document parsing.
3. The target application processes the document with `LatexBackendOptions(tikz_engine="tectonic")` enabled.
4. Docling writes the malicious LaTeX content into a temporary file for processing by the Tectonic binary.
5. The Tectonic engine executes the compilation, during which it processes the attacker's embedded primitives, bypassing directory staging restrictions.
6. If `allow_shell_escape` is enabled, the `\write18` primitive triggers the execution of arbitrary shell commands on the host operating system.
7. The process reads local files or overwrites system configurations, leading to information disclosure or full system compromise.

## Impact

Successful exploitation allows unauthenticated attackers to read arbitrary files accessible to the Docling process and overwrite sensitive files. In configurations where shell escape is permitted, attackers achieve remote code execution, potentially leading to a full compromise of the host system. This vulnerability affects any service or application utilizing Docling's LaTeX backend processing capabilities.

## Recommendation

- Upgrade Docling and Docling-slim to version 2.132.0 or later immediately to apply the patch for CVE-2026-105744.
- Audit existing Docling implementations to ensure `tikz_engine_allow_shell_escape` is set to `False` by default.
- If upgrading is not immediately possible, execute document processing tasks in highly isolated environments (e.g., restricted containers with no network access, read-only filesystems, and no host volume mounts).
- Implement monitoring for unexpected subprocess spawning from document parsing services.
