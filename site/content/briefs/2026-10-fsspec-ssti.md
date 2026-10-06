---
title: Remote Code Execution via Server-Side Template Injection in fsspec ReferenceFileSystem
slug: 2026-10-fsspec-ssti
description: The fsspec library contains an un-sandboxed Jinja2 template injection vulnerability in its Kerchunk reference processing logic, allowing arbitrary code execution when processing malicious data catalogues.
date: "2026-10-06T00:46:33Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:fsspec_project:fsspec:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - rce
  - vulnerability
  - python
products:
  - fsspec (>= 0.9.0, < 2026.6.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The parser renders fields from this JSON through un-sandboxed jinja2.Template(...).render(...) calls... resulting in arbitrary Python code execution.
    confidence_band: high
cves:
  - id: CVE-2026-104851
    cvss: 8.8
    epss: 0.00317
references:
  - https://github.com/advisories/GHSA-27vj-qcqg-25rc
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104851
action_plan:
  priority: immediate_escalation
  owners:
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Upgrade fsspec to 2026.6.0 or later
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates upgrading to 2026.6.0 or later for remediation.
  mitigation_plan:
    - priority: immediate
      action: Upgrade fsspec to 2026.6.0 or later
      owner: IT Operations
      addresses: CVE-2026-104851
      evidence: Source provided fixed version for CVE-2026-104851.
---

The `fsspec` library, specifically the `ReferenceFileSystem` implementation used for the Kerchunk data format, contains an un-sandboxed Server-Side Template Injection (SSTI) vulnerability. The parser processes "references" JSON documents and renders fields using `jinja2.Template(...).render(...)` without security restrictions. Vulnerable sinks exist within the `_process_references1._render_jinja`, `_process_templates`, and `_process_gen` methods in `fsspec/implementations/reference.py`. 

An attacker who controls a references JSON document can achieve arbitrary Python code execution on the victim's machine. This occurs as soon as the victim opens the file using `fsspec.filesystem("reference", fo=URL)` or via high-level consumers such as `xarray.open_dataset`. This vulnerability impacts all versions from 0.9.0 through 2026.5.x. The exploitation path mirror patterns seen in previous Jinja2-based RCE vulnerabilities where externally-sourced templates were rendered in unrestricted environments.

## Attack Chain

1. Attacker crafts a malicious JSON document containing Jinja2 SSTI payloads (e.g., using `__init__.__globals__` to access system commands).
2. Attacker hosts the malicious JSON document at a public or accessible URL.
3. Attacker induces a victim (e.g., a data scientist or automated pipeline) to load the URL using `fsspec` or a library that consumes it, such as `xarray`.
4. The victim application calls `fsspec.filesystem("reference", fo=URL)` to initialize the filesystem.
5. The `ReferenceFileSystem` logic parses the JSON and reaches one of the vulnerable sinks, specifically `_process_gen`, which is triggered unconditionally for any JSON containing a `gen` field.
6. The `jinja2.Template.render` call processes the malicious payload.
7. The Jinja2 environment executes the injected Python code on the host machine.
8. The attacker achieves arbitrary code execution (RCE) with the privileges of the victim application.

## Impact

Successful exploitation results in arbitrary remote code execution on systems processing Kerchunk data catalogues. This is critical for the Pangeo, Earth-observation, and climate data-science ecosystems, where Kerchunk is widely adopted. Impacted environments include interactive Jupyter notebook servers, automated batch processing pipelines, and local analysis workstations. Victims are compromised immediately upon opening a malicious reference file, leading to potential data exfiltration or lateral movement within the environment.

## Recommendation

Prioritize the following actions to mitigate this vulnerability:
- Upgrade `fsspec` to version 2026.6.0 or later immediately to incorporate the sandboxed environment fix.
- Implement strict network filtering on internal data-science environments to restrict outbound connections to untrusted storage URLs.
- Audit all automated pipelines consuming Kerchunk files to ensure they are not processing files from unverified or user-controlled sources.
- Patch CVE-2026-104851 across all production and development environments using `fsspec`.
