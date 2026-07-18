---
title: Arbitrary Code Execution in uproot via Crafted ROOT Files (CVE-2026-9147)
slug: 2026-07-uproot-rce
description: A vulnerability, CVE-2026-9147, in the uproot library allows arbitrary Python code execution when processing crafted ROOT files due to improper handling of streamer metadata fields during dynamic code generation, impacting applications that open or process untrusted ROOT files.
date: "2026-07-18T13:18:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - python
  - code-execution
vendors:
  - uproot project
products:
  - uproot
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker who can supply a crafted ROOT file can place Python expression-breaking content into a streamer metadata field. When uproot generates and invokes the corresponding reader method, the injected Python expression is evaluated in the context of the process opening the file, resulting in arbitrary Python code execution.
    confidence_band: high
cves:
  - id: CVE-2026-9147
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-9147
---

A critical vulnerability, tracked as CVE-2026-9147, has been identified in the `uproot` Python library, which is used for reading and writing ROOT files. `uproot` dynamically generates and compiles Python class source code at runtime from ROOT `TStreamerInfo` records found within these files. The vulnerability arises because certain file-controlled streamer metadata fields, such as streamer element names, are directly interpolated into the generated Python source code without proper safe quoting mechanisms like `repr()` or the `!r` format specifier. An attacker can exploit this by crafting a malicious ROOT file containing Python expression-breaking content within a streamer metadata field. When an application utilizes `uproot` to open or process such a file, the injected Python expression is evaluated in the context of the running process, leading to arbitrary Python code execution. This poses a significant risk to applications that process untrusted ROOT files, enabling attackers to fully compromise the host system.

## Attack Chain

1. An attacker crafts a malicious ROOT file containing specially malformed `TStreamerInfo` records.
2. Within these `TStreamerInfo` records, the attacker embeds Python expression-breaking content into streamer metadata fields, such as streamer element names.
3. The attacker delivers this crafted ROOT file to a victim, potentially through email, download, or by placing it in a shared repository.
4. A victim's application, which uses the `uproot` library, attempts to open or process the malicious ROOT file.
5. `uproot` dynamically generates Python class source code based on the `TStreamerInfo` records, interpolating the attacker-controlled metadata fields directly into the source.
6. Due to the lack of safe quoting, the injected Python expression-breaking content becomes part of the generated Python code.
7. `uproot` compiles and invokes the corresponding reader method, causing the injected Python expression to be evaluated.
8. Arbitrary Python code is executed on the victim's system with the privileges of the affected application, leading to full system compromise or data exfiltration.

## Impact

Successful exploitation of CVE-2026-9147 results in arbitrary Python code execution on the system processing the malicious ROOT file. This allows an attacker to take complete control of the affected application and potentially the underlying operating system. The specific damage could range from data theft and modification to the installation of additional malware, remote access tools, or complete system compromise. Organizations processing ROOT files from untrusted sources, particularly in scientific research, data analysis, or high-energy physics domains, are at risk. No specific victim counts or targeted sectors are provided, but any application using `uproot` to handle external ROOT files is potentially vulnerable.

## Recommendation

* Patch CVE-2026-9147 by upgrading the `uproot` library to a version that addresses this vulnerability immediately across all affected systems.
* Implement strict validation and sanitization for all ROOT files ingested from untrusted or external sources to prevent the processing of malicious content.
* Reduce the attack surface by limiting the types of files applications can process and ensuring `uproot`-using applications run with the least necessary privileges.
* Monitor process creation logs for unusual Python script executions originating from applications that typically process data files, which could indicate exploitation of CVE-2026-9147.
