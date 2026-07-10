---
title: PraisonAI Arbitrary Code Execution Vulnerability (CVE-2026-40156)
slug: 2024-01-praisonai-code-exec
description: PraisonAI versions before 4.5.128 are vulnerable to arbitrary code execution due to the automatic loading and execution of a 'tools.py' file from the current working directory without proper validation or user consent, potentially allowing attackers to execute malicious code by placing a rogue file in a PraisonAI execution directory.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-40156
  - code-execution
  - praisonai
vendors:
  - PraisonAI
products:
  - PraisonAI
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1202
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-40156
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40156
rules:
  - title: Detect PraisonAI tools.py Execution
    description: Detects the execution of tools.py by PraisonAI, indicative of potential exploitation of CVE-2026-40156.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - process_creation
      - linux
  - title: Detect tools.py File Creation in PraisonAI Directories
    description: Detects the creation of tools.py files in directories commonly used by PraisonAI, which could indicate an attempt to exploit CVE-2026-40156.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1202
    data_sources:
      - file_event
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, is susceptible to arbitrary code execution in versions prior to 4.5.128. This vulnerability stems from the application's automatic loading of a `tools.py` file from the current working directory. This loading process leverages `importlib.util.spec_from_file_location` and immediately executes module-level code using `spec.loader.exec_module()` without any user consent, validation, or sandboxing mechanisms. The vulnerability arises because `tools.py` is loaded implicitly, even if not referenced in any configuration files. An attacker who can place a malicious `tools.py` file in a directory where PraisonAI is executed can achieve arbitrary code execution upon startup. This vulnerability violates the expected security boundary and makes automated systems running PraisonAI susceptible to compromise. The vulnerability is identified as CVE-2026-40156 and is resolved in version 4.5.128.

## Attack Chain

1. The attacker identifies a system running a vulnerable version of PraisonAI (versions prior to 4.5.128).
2. The attacker gains write access to a directory where PraisonAI is executed. This could be achieved through various means, such as exploiting a separate vulnerability or leveraging existing access.
3. The attacker crafts a malicious `tools.py` file containing arbitrary code.
4. The attacker places the malicious `tools.py` file into the PraisonAI working directory.
5. PraisonAI is started (either manually or automatically, such as through a scheduled task or CI/CD pipeline).
6. PraisonAI automatically loads the `tools.py` file using `importlib.util.spec_from_file_location`.
7. The code within `tools.py` is immediately executed via `spec.loader.exec_module()`, granting the attacker arbitrary code execution within the context of the PraisonAI process.
8. The attacker's code can perform actions such as installing malware, creating new user accounts, or exfiltrating sensitive data.

## Impact

Successful exploitation of CVE-2026-40156 allows an attacker to execute arbitrary code on the affected system. This could lead to complete system compromise, including data theft, malware installation, and denial of service. The severity is high due to the ease of exploitation (simply placing a file in a directory) and the potential for significant damage. Victims would likely include organizations utilizing PraisonAI in automated or user-driven workflows.

## Recommendation

*   Upgrade PraisonAI to version 4.5.128 or later to patch CVE-2026-40156.
*   Implement strict access controls on directories where PraisonAI is executed to prevent unauthorized file creation, mitigating the impact of CVE-2026-40156.
*   Deploy the Sigma rule `Detect PraisonAI tools.py Execution` to identify instances where a `tools.py` file is loaded from unexpected locations.
*   Enable process monitoring and auditing to detect suspicious activity originating from PraisonAI processes following exploitation of CVE-2026-40156.
