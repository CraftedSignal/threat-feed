---
title: datamodel-code-generator Arbitrary Local File Read Vulnerability
slug: 2026-07-datamodel-code-generator-file-read
description: The `datamodel-code-generator` library (versions <= 0.61.0) is vulnerable to an unauthenticated path traversal and arbitrary local file read (CVE-2026-55389), allowing an attacker to supply a crafted JSON-Schema with `$ref` fields pointing to local files using `file://` URIs or `../` path traversal sequences, bypassing the `--no-allow-remote-refs` security control, which leads to information disclosure of sensitive data and enables filesystem mapping.
date: "2026-07-28T21:53:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - path-traversal
  - information-disclosure
  - python
products:
  - datamodel-code-generator <= 0.61.0
affected_os:
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: read any file the process user can read
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: map the host filesystem and recover absolute paths
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-8359-h9fx-j6v9
iocs:
  - type: url
    value: https://gist.github.com/thegr1ffyn/2a87e81f985883acc30d0118c52da4d3
ioc_counts:
  url: 1
---

A high-severity arbitrary local file read vulnerability (CVE-2026-55389) has been discovered in `datamodel-code-generator` versions 0.61.0 and earlier. This Python library is commonly used in development workflows, CI/CD pipelines, and multi-tenant services to generate data models from OpenAPI or JSON-Schema specifications. The vulnerability allows an attacker to craft a malicious JSON-Schema containing `$ref` fields that reference arbitrary local files on the system running the generator. This can be achieved using `file://` URIs for absolute paths or `../` sequences for relative path traversal, effectively bypassing the `--no-allow-remote-refs` security control. Successful exploitation leads to unauthorized information disclosure, including sensitive data like `/etc/passwd`, private keys (e.g., `id_rsa`), configuration files, and allows mapping of the host's filesystem layout. The fix was released in version 0.62.0, which applies the remote-ref gate to `file://` references and local JSON Schema refs outside the input base path.

## Attack Chain

1. **Attacker crafts malicious JSON-Schema:** An attacker creates a JSON-Schema file (e.g., `probe.json`) containing a `$ref` field with a crafted URI.
2. **References sensitive local files:** The `$ref` field uses a `file://` scheme to point to an absolute path (e.g., `file:///etc/passwd`) or `../` path traversal sequences (e.g., `../.ssh/id_rsa`) to reference arbitrary local files.
3. **Victim executes `datamodel-code-generator`:** A victim's system, such as a CI/CD pipeline, development environment, or multi-tenant service, invokes the `datamodel-code-generator` utility to process the attacker's untrusted schema (e.g., `datamodel-codegen --input probe.json --output o.py`).
4. **Vulnerable reference resolution:** `datamodel-code-generator`'s internal logic, specifically within the `_get_ref_body` function, attempts to resolve the `$ref` target.
5. **Bypasses security control:** The vulnerability allows the `file://` scheme to be explicitly exempted from the `allow_remote_refs` check, or for relative paths, the `is_relative_to(base_path)` check is not enforced, allowing traversal outside the base directory.
6. **Arbitrary file read:** The vulnerable code path (`_get_ref_body_from_url` or `_get_ref_body_from_remote`) proceeds to load the content of the arbitrary local file referenced in the `$ref` field.
7. **Filesystem oracle and information disclosure:** Depending on the target file's content and permissions, the tool either generates an error message (e.g., "TypeError: Expected dict, got str") indicating the file was read and parsed, or directly incorporates schema-shaped secrets (e.g., from `const`/`default`/`enum`/`description` fields) from the read file into the generated Python code.
8. **Exfiltration via generated code or errors:** The attacker receives the generated Python code (if it contains secrets) or observes the process's error messages (providing an oracle for file existence and permissions), thereby exfiltrating sensitive information or mapping the victim's filesystem layout.

## Impact

This vulnerability leads to arbitrary local file read (CWE-22) and subsequent information disclosure (CWE-200), bypassing a documented security control (`--no-allow-remote-refs`). Any application, CI pipeline, or multi-tenant service running `datamodel-code-generator` on untrusted schemas is at risk. Attackers can read any file accessible to the process user, including sensitive system files like `/etc/passwd`, private keys (e.g., PEM `id_rsa`), and configuration files (e.g., service-account JSON, Kubernetes secret manifests). This allows for host filesystem mapping by probing arbitrary paths and exfiltrating secret values verbatim if they are embedded within schema-shaped nodes. The issue does not require authentication or special privileges, making it a critical threat for environments processing untrusted input.

## Recommendation

* Upgrade `pip/datamodel-code-generator` to version `0.62.0` or higher to remediate CVE-2026-55389.
* Ensure the `--no-allow-remote-refs` flag is enabled when invoking `datamodel-code-generator` with untrusted input, as this flag's bypass for `file://` references was fixed in version `0.62.0`.
* Restrict execution permissions for `datamodel-code-generator` processes to the minimum necessary files and directories to limit potential damage from exploitation.
* Block the proof-of-concept URL `https://gist.github.com/thegr1ffyn/2a87e81f985883acc30d0118c52da4d3` at network perimeters to prevent access to known exploit code.
