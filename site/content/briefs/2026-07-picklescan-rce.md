---
title: 'CVE-2025-71342: picklescan Remote Code Execution Vulnerability'
slug: 2026-07-picklescan-rce
description: A critical vulnerability (CVE-2025-71342) exists in picklescan versions prior to 0.0.30, where it fails to detect malicious code embedded in Python pickle files by leveraging `idlelib.run.Executive.runcode` in reduce methods, allowing attackers to conceal and execute arbitrary code during `pickle.load` operations, leading to remote code execution (RCE) and potential supply chain attacks, particularly impacting PyTorch models.
date: "2026-07-04T02:18:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - rce
  - supply-chain
  - python
  - pickle
  - pytorch
vendors:
  - picklescan
products:
  - picklescan < 0.0.30
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can embed undetected code in pickle files that executes during pickle.load, enabling remote code execution
    confidence_band: high
cves:
  - id: CVE-2025-71342
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2025-71342
  - https://github.com/mmaitre314/picklescan/security/advisories/GHSA-m869-42cg-3xwr
  - https://www.vulncheck.com/advisories/picklescan-undetected-remote-code-execution-via-idlelib-run-executive-runcode
---

CVE-2025-71342 identifies a significant vulnerability within `picklescan` versions prior to 0.0.30, a Python library designed to scan pickle files for malicious content. The flaw stems from `picklescan`'s inability to adequately detect embedded malicious code when attackers specifically use `idlelib.run.Executive.runcode` within the reduce methods of a Python pickle file. This oversight allows threat actors to craft seemingly benign pickle files that, upon deserialization using `pickle.load`, will execute arbitrary code. The vulnerability poses a severe risk, particularly for environments handling untrusted pickle files, such as those involving machine learning models (e.g., PyTorch models). Successful exploitation can lead to remote code execution (RCE) on the target system and facilitate widespread supply chain attacks by injecting malicious logic into widely distributed models or data.

## Attack Chain

1.  An attacker crafts a specially designed Python pickle file containing arbitrary code.
2.  The malicious code is embedded within the pickle file's reduce methods, specifically leveraging `idlelib.run.Executive.runcode` to obscure its true intent.
3.  The attacker then distributes this malicious pickle file, potentially by injecting it into a software supply chain (e.g., a shared machine learning model repository).
4.  A victim system or application, such as a PyTorch model loader, downloads or receives the compromised pickle file.
5.  The application attempts to deserialize the pickle file using Python's `pickle.load()` function.
6.  During the deserialization process, `picklescan` (if present and vulnerable, i.e., version < 0.0.30) fails to identify the `idlelib.run.Executive.runcode` as a malicious primitive.
7.  The embedded arbitrary code within the pickle file's reduce methods is consequently executed by the Python interpreter on the victim's system.
8.  This results in remote code execution (RCE), allowing the attacker to compromise the host system and potentially exfiltrate data or establish persistence.

## Impact

The successful exploitation of CVE-2025-71342 carries severe consequences, primarily remote code execution (RCE) with a CVSS v3.1 base score of 8.1 (High severity). This vulnerability can lead to complete compromise of the affected system's confidentiality and integrity, as attackers gain the ability to execute arbitrary commands. The primary risk lies in supply chain attacks, where malicious pickle files can be distributed through legitimate channels, infecting numerous downstream users. PyTorch models, often distributed as pickle files, are particularly vulnerable, meaning that compromised models could propagate malware to researchers, developers, and production systems globally, leading to widespread data theft, system sabotage, or further network penetration.

## Recommendation

*   Immediately update `picklescan` to version 0.0.30 or later to remediate CVE-2025-71342.
*   Implement strict validation and sandboxing for deserialization of Python pickle files, especially those from untrusted or external sources.
*   Educate development teams on the risks associated with deserializing untrusted data, specifically in the context of CVE-2025-71342 and `pickle.load`.
*   Review existing practices for handling and loading machine learning models (e.g., PyTorch models) to ensure only verified and scanned pickle files are processed.
