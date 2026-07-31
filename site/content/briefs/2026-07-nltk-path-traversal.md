---
title: NLTK NKJPCorpusReader Path Traversal Vulnerability
slug: 2026-07-nltk-path-traversal
description: A path-traversal vulnerability in NLTK's NKJPCorpusReader allows attackers to read arbitrary files by bypassing the nltk.pathsec security sandbox.
date: "2026-07-31T19:30:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - cve-2026-12072
  - library-vulnerability
vendors:
  - Natural Language Toolkit
products:
  - NLTK (<= 3.9.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The reader builds the file path with no containment check and opens it with the builtin open(), so it bypasses NLTK's nltk.pathsec sandbox.
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-6hm5-jgcp-p838
---

The Natural Language Toolkit (NLTK) version 3.9.4 and earlier contains a critical path-traversal vulnerability (CVE-2026-12072) within the `NKJPCorpusReader` class. The component fails to validate or sanitize the `fileids` parameter used in its corpus reading methods (e.g., `header`, `raw`, `words`). Instead of utilizing the `nltk.pathsec` security framework, which is designed to prevent directory traversal and enforce strict access control, `NKJPCorpusReader` relies on insecure string concatenation to build file paths and subsequently invokes Python's built-in `open()` function.

This architectural flaw persists even when `nltk.pathsec.ENFORCE = True` is set, a configuration specifically intended to protect multi-tenant and web-based applications from unauthorized file system access. An attacker capable of influencing the input to these methods can escape the intended corpus directory, leading to unauthorized disclosure of sensitive files on the host system. The vulnerability affects a wide range of NLTK corpus readers that share the same insecure pattern of using raw file operations over the provided security API.

## Attack Chain

1. Attacker identifies an application endpoint or script that accepts user-supplied input used as a `fileids` argument for NLTK's `NKJPCorpusReader`.
2. Attacker crafts a malicious path string containing directory traversal sequences (e.g., `../../../../`) to escape the configured corpus root directory.
3. The application passes the malicious string into the `NKJPCorpusReader.header()` or related corpus reading method.
4. `NKJPCorpusReader` performs plain string concatenation of the corpus root and the attacker-controlled `fileids` without normalization or security validation.
5. The resulting path points to a sensitive file on the host filesystem (e.g., `/etc/passwd` or configuration files).
6. The `NKJPCorpusReader` method calls the Python built-in `open()` function directly with the resolved malicious path.
7. The `nltk.pathsec` sandbox is never consulted, bypassing the `ENFORCE=True` security configuration.
8. The application returns the content of the unintended file to the attacker, resulting in unauthorized data exfiltration.

## Impact

Successful exploitation allows for the arbitrary reading of files on the host operating system with the privileges of the service account running the NLTK-based application. This poses a significant risk to web and multi-tenant environments where NLTK is utilized to process untrusted user input. Exposure of local configuration files, API keys, or system credentials could lead to full system compromise. The vulnerability affects any software utilizing NLTK <= 3.9.4 for corpus analysis.

## Recommendation

* Update NLTK to the latest version once a patch is released that addresses the `NKJPCorpusReader` path validation logic.
* Implement strict input validation for any user-controlled data intended to act as a file path or identifier within NLTK readers.
* Audit application code for any custom use of `os.path.join` or string concatenation when constructing file paths passed to NLTK corpus objects, ensuring that `FileSystemPathPointer.open()` is used instead of the built-in `open()`.
* Restrict the privileges of the system user running the NLTK-dependent application to the minimum necessary directory access using OS-level controls (e.g., AppArmor, SELinux, or container volume restrictions).
