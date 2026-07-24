---
title: CVE-2025-71408 NLTK Eval Injection Vulnerability
slug: 2026-07-nltk-eval-injection
description: An eval injection vulnerability exists in the nltk.collocations module of NLTK (Natural Language Toolkit) versions prior to 3.9.3, allowing an attacker to exploit this by controlling command-line arguments passed to collocations.py, which are then unsafely passed to eval() enabling remote code execution on the affected system.
date: "2026-07-24T22:18:25Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - eval-injection
  - remote-code-execution
  - python
vendors:
  - NLTK
products:
  - NLTK (Natural Language Toolkit) < 3.9.3
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker who controls command-line arguments to execute arbitrary Python code.
    confidence_band: high
cves:
  - id: CVE-2025-71408
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71408
---

A critical eval injection vulnerability, identified as CVE-2025-71408, has been discovered in the Natural Language Toolkit (NLTK) Python library, affecting all versions prior to 3.9.3. This flaw resides within the `nltk.collocations` module, specifically when the `collocations.py` script is directly invoked via the command line. The vulnerability arises because the script's `__main__` block passes user-supplied command-line arguments directly to Python's `eval()` function without adequate sanitization or allowlist validation. An attacker who can control these command-line arguments can inject arbitrary Python expressions, bypassing the intended attribute lookup mechanism. This allows for the execution of arbitrary Python code, including operating system commands through Python's `os` module, leading to remote code execution (RCE) on the compromised system. The vulnerability presents a significant risk to applications and environments utilizing affected NLTK versions, especially those that process untrusted input via `collocations.py`.

## Attack Chain

1. An attacker crafts a malicious Python expression designed to execute arbitrary code or OS commands.
2. The attacker delivers or injects this malicious expression into the command-line arguments intended for the `collocations.py` script.
3. A vulnerable system or application executes `collocations.py`, passing the attacker-controlled command-line arguments.
4. The `__main__` block within `collocations.py` directly processes these arguments and feeds them into the `eval()` function.
5. Due to the `eval injection` vulnerability, the malicious Python expression is evaluated instead of benign data.
6. Arbitrary Python code, including system-level commands leveraging the `os` module (e.g., `os.system("malicious_command")`), is executed on the host.
7. The attacker achieves remote code execution on the system, potentially leading to full system compromise, data exfiltration, or further lateral movement.

## Impact

Successful exploitation of CVE-2025-71408 grants attackers arbitrary code execution capabilities on the host system where vulnerable NLTK versions are deployed. This can lead to complete system compromise, allowing attackers to install malware, establish persistence, exfiltrate sensitive data, or disrupt operations. The broad use of NLTK in data science, academic research, and various applications suggests a wide potential impact across multiple sectors if not patched. The CVSS v3.1 Base Score of 7.8 indicates a high severity risk.

## Recommendation

* Prioritize patching all instances of NLTK (Natural Language Toolkit) to version 3.9.3 or later to remediate CVE-2025-71408 immediately.
* Implement robust input validation and sanitization for any application that passes untrusted user input to command-line arguments, especially when those arguments are processed by Python scripts that may use functions like `eval()`.
* Monitor process creation logs for unusual child processes spawned by Python interpreters, particularly if `collocations.py` is known to run on your systems.
