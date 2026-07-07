---
title: Langroid File Tools Path Traversal Vulnerability (CVE-2026-50181)
slug: 2026-07-langroid-path-traversal
description: A path traversal vulnerability (CVE-2026-50181) exists in Langroid's `ReadFileTool` and `WriteFileTool` components (versions <= 0.63.0), allowing an attacker to read or write arbitrary files outside the configured `curr_dir` via crafted `file_path` arguments, potentially leading to sensitive information disclosure or unauthorized file modification in applications exposing these tools to user or LLM input.
date: "2026-07-03T12:11:45Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - python-library
  - vulnerability
  - llm-agent
vendors:
  - Langroid
products:
  - langroid (<= 0.63.0)
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: Reading files outside the intended workspace.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Exposing local secrets, configuration files, source files, environment files, or other project-adjacent files.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: Modifying files outside the intended project directory if WriteFileTool is enabled.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-fg23-3346-88f5
  - https://github.com/user-attachments/files/28333958/Langroid.CVE.Report.pdf
---

A significant path traversal vulnerability, tracked as CVE-2026-50181, has been identified in Langroid's `ReadFileTool` and `WriteFileTool` components, affecting all versions up to and including 0.63.0. The vulnerability stems from the tools' failure to properly validate and enforce path boundaries after changing the process working directory to a `curr_dir` (current directory). While the tools intend to restrict file operations to this `curr_dir`, they do not resolve the user-supplied `file_path` to ensure it remains within this boundary. This oversight allows an attacker to use path traversal sequences, such as `../`, within the `file_path` argument to access files located outside the intended `curr_dir`. The impact is particularly critical for applications that expose these file tools to user-controlled input, Large Language Model (LLM) agents, or delegated coding/documentation agents, as it can lead to unauthorized reading of sensitive files (e.g., secrets, configuration files) or modification of arbitrary files, compromising data confidentiality and integrity. The issue is present in `langroid/agent/tools/file_tools.py` and `langroid/utils/system.py`.

## Attack Chain

1.  **Identify Vulnerable Application:** An attacker identifies an application that integrates Langroid and exposes its `ReadFileTool` or `WriteFileTool` in a way that allows user-controlled input to influence the `file_path` argument (e.g., via an LLM agent interface or a user-facing API).
2.  **Craft Malicious Path:** The attacker crafts a `file_path` argument containing path traversal sequences, such as `../`, to reference a file outside the intended sandbox or working directory (e.g., `../etc/passwd` for reading, or `../malicious_script.sh` for writing).
3.  **Invoke Vulnerable Tool:** The attacker sends the crafted `file_path` as input to the application, which then passes it directly to an instance of `ReadFileTool` or `WriteFileTool`.
4.  **Directory Change (Internal):** Internally, the Langroid tool changes the process's current working directory to the configured `curr_dir` (e.g., `/var/app/sandbox/`).
5.  **Unvalidated Path Resolution:** The tool then proceeds to open or create the file using the provided `file_path` argument. Due to the lack of proper validation, the `../` sequences are honored, causing the path to resolve outside the `curr_dir` (e.g., `/var/etc/passwd`).
6.  **Execute Unauthorized File Operation:** The Langroid tool performs the requested operation (read or write) on the arbitrarily resolved file path outside the intended boundary.
7.  **Information Disclosure / Data Modification:** If `ReadFileTool` was used, the contents of the sensitive file are disclosed to the attacker. If `WriteFileTool` was used, the attacker can modify or create arbitrary files, potentially leading to further compromise, persistence, or data integrity violations.

## Impact

This vulnerability can severely impact applications that enable Langroid's file tools and rely on the `curr_dir` parameter to establish a secure sandbox, project, or workspace boundary. If exploited, an attacker can read files outside the intended workspace, leading to the exposure of sensitive local secrets, configuration files, source code, environment files, or other critical project-adjacent data. Conversely, by exploiting `WriteFileTool`, an attacker could modify or create arbitrary files outside the designated project directory, which could lead to code injection, defacement, or disruption of services. The severity of the impact is contingent on how the Langroid file tools are exposed and the nature of the application's file system structure.

## Recommendation

*   **Patch CVE-2026-50181:** Upgrade the Langroid library to a version patched for CVE-2026-50181 immediately.
*   **Implement Path Validation:** For applications using Langroid file tools, implement robust path validation logic before passing any user-controlled or LLM-generated `file_path` arguments to `ReadFileTool` or `WriteFileTool`. Ensure all resolved paths remain strictly within the intended `curr_dir`.
*   **Review `curr_dir` Usage:** Audit all instances where `ReadFileTool` and `WriteFileTool` are used, verifying that the `curr_dir` is correctly configured and that no sensitive files are reachable via path traversal from this directory.
