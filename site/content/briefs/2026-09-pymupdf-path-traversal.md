---
title: Path Traversal Vulnerability in PyMuPDF Font Processing
slug: 2026-09-pymupdf-path-traversal
description: PyMuPDF versions through 1.28.2 contain a path traversal vulnerability in the extract_objects() function, allowing attackers to perform arbitrary file writes via crafted document font metadata.
date: "2026-09-14T19:35:53Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:artifex:pymupdf:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - path-traversal
  - software-library
vendors:
  - Artifex Software
products:
  - PyMuPDF (<= 1.28.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can supply a crafted PDF, EPUB, XPS, or FB2 file with a BaseFont name containing encoded path separators that decode to ../ sequences or absolute paths, causing arbitrary file writes outside the intended output directory.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82035
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development
  immediate_actions:
    - action: Upgrade PyMuPDF to version > 1.28.2
      owner: Development
      due: 48h
      evidence: Source identifies commit b2c8f3a as the fix
  mitigation_plan:
    - priority: immediate
      action: Upgrade PyMuPDF
      owner: IT Operations
      addresses: CVE-2026-82035
      evidence: NVD vulnerability report
---

PyMuPDF through version 1.28.2 is vulnerable to a path traversal flaw located in the font branch of the extract_objects() function within src/__main__.py. The vulnerability arises because the library fails to sanitize document-controlled 'BaseFont' names before joining them with a user-supplied output directory. An attacker can supply a malicious PDF, EPUB, XPS, or FB2 document containing a BaseFont name manipulated with encoded path separators or dot-dot sequences. When a victim or automated service processes this document using the vulnerable extract_objects() function, the library may resolve the path to a location outside the intended directory. This permits arbitrary file writes on the host system, which could be leveraged to overwrite critical configuration files, drop webshells, or perform other malicious operations depending on the environment where the library is deployed. This issue was addressed in commit b2c8f3a.

## Impact

Successful exploitation allows for arbitrary file writes with the permissions of the user running the PyMuPDF processing script or application. This vulnerability poses a significant risk to document processing pipelines, web applications that accept user-submitted files for rendering or extraction, and local utilities that process untrusted documents. If exploited, an attacker could potentially achieve remote code execution by overwriting binaries or configuration files, leading to full system compromise.

## Recommendation

* Upgrade the PyMuPDF library to a version containing the fix for commit b2c8f3a (version 1.28.3 or later) immediately.
* Audit applications using PyMuPDF to identify instances where the extract_objects() function is invoked on untrusted or user-supplied document files.
* Implement strict filesystem sandboxing or containerization for services that process document files to limit the potential impact of arbitrary file write vulnerabilities.
