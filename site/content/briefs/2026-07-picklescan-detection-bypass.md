---
title: CVE-2025-71343 — picklescan Detection Bypass via Malicious Pickle Files
slug: 2026-07-picklescan-detection-bypass
description: A deserialization vulnerability, CVE-2025-71343, in picklescan before version 0.0.30 allows attackers to craft malicious pickle files that evade detection and lead to arbitrary code execution when loaded via `pickle.load()`.
date: "2026-07-04T02:19:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - deserialization
  - remote-code-execution
  - python
  - vulnerability
  - detection-bypass
vendors:
  - picklescan
products:
  - picklescan < 0.0.30
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can craft malicious pickle files with embedded code that evades detection but executes arbitrary commands when pickle.load() is called.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1027
    technique_name: Obfuscated Files or Information
    evidence: picklescan before 0.0.30 fails to detect malicious pickle files that exploit lib2to2.pgen2.pgen.ParserGenerator.make_label function... Attackers can craft malicious pickle files with embedded code that evades detection.
    confidence_band: high
cves:
  - id: CVE-2025-71343
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71343
  - https://github.com/mmaitre314/picklescan/security/advisories/GHSA-p9w7-82w4-7q8m
  - https://www.vulncheck.com/advisories/picklescan-arbitrary-code-execution-via-lib2to3-pgen2-pgen-parsergenerator-make-label-detection-bypass
---

CVE-2025-71343 describes a critical vulnerability affecting `picklescan` versions prior to 0.0.30. This flaw stems from a detection bypass related to the `lib2to3.pgen2.pgen.ParserGenerator.make_label` function within the `reduce` method, which is a key component in parsing Python bytecode. Attackers can leverage this vulnerability to craft highly sophisticated malicious pickle files. These files are specifically designed to contain embedded arbitrary commands but will successfully evade `picklescan`'s security checks. When an application on a vulnerable system then uses the standard `pickle.load()` function to deserialize one of these malicious files, the embedded commands are executed, resulting in arbitrary code execution. This poses a significant risk to systems that process untrusted pickle files, as the primary defense mechanism (`picklescan`) is rendered ineffective against this specific evasion technique.

## Attack Chain

1.  Attacker crafts a malicious Python pickle file containing arbitrary code, specifically exploiting the `lib2to3.pgen2.pgen.ParserGenerator.make_label` function's `reduce` method to bypass `picklescan`'s detection.
2.  The malicious pickle file is delivered to a target system, potentially through methods such as email attachments, malicious web downloads, or integration into a compromised software supply chain.
3.  An application or user on the target system processes or scans the received pickle file using `picklescan` version prior to 0.0.30.
4.  Due to CVE-2025-71343, `picklescan` fails to identify the embedded malicious payload, incorrectly marking the file as benign.
5.  A Python application or script on the target system subsequently loads the "undetected" malicious pickle file using `pickle.load()`.
6.  During the deserialization process, the embedded arbitrary code within the pickle file is executed in the context of the Python application.
7.  The attacker achieves arbitrary command execution on the compromised system, potentially leading to full system compromise, data exfiltration, or further lateral movement.

## Impact

The successful exploitation of CVE-2025-71343 allows an attacker to achieve arbitrary code execution on systems that process untrusted pickle files using vulnerable versions of `picklescan`. This can lead to complete system compromise, unauthorized access to sensitive data, installation of malware, or disruption of services. While no specific victim counts are provided, any organization or individual processing Python pickle files in environments where `picklescan` is used for security vetting (especially in data science, machine learning, or software development contexts) is at risk. The undetected nature of the attack makes it particularly dangerous, as security tools designed to prevent such threats are bypassed.

## Recommendation

*   Update `picklescan` to version 0.0.30 or later immediately to patch CVE-2025-71343 and address the detection bypass vulnerability.
*   Implement strict controls on the ingestion and processing of untrusted pickle files, regardless of `picklescan`'s output, especially from external or unverified sources.
*   Educate users and developers about the risks associated with deserializing untrusted data, specifically in the context of Python pickle files, to prevent arbitrary code execution (CWE-502).
