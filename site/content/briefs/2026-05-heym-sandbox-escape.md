---
title: Heym Sandbox Escape Vulnerability (CVE-2026-45227)
slug: 2026-05-heym-sandbox-escape
description: Heym before 0.0.21 is vulnerable to a sandbox escape (CVE-2026-45227) in the custom Python tool executor, allowing authenticated workflow authors to bypass restrictions and execute arbitrary host commands as the backend service user.
date: "2026-05-12T22:18:20Z"
type: threat
types:
  - threat
severities:
  - high
tags:
  - sandbox-escape
  - python
  - code-execution
vendors:
  - Heym
products:
  - Heym
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-45227
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-45227
  - CVE-2026-45227
rules:
  - title: Detect Heym Sandbox Escape Attempt via Import
    description: Detects CVE-2026-45227 exploitation - Attempts to import restricted modules (os, subprocess) within the Heym Python tool executor, indicating a potential sandbox escape attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect Heym Sandbox Escape Attempt via Introspection
    description: Detects CVE-2026-45227 exploitation - Attempts to access __import__ function indicating a potential sandbox escape attempt.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Heym before version 0.0.21 contains a critical sandbox escape vulnerability, identified as CVE-2026-45227, within its custom Python tool executor. This flaw enables authenticated workflow authors to circumvent intended sandbox restrictions by leveraging object-graph introspection primitives. By exploiting this vulnerability, attackers can regain access to the unrestricted `__import__` function, enabling the import of typically blocked modules such as `os` and `subprocess`. This access further allows attackers to access inherited backend environment variables, potentially exposing sensitive information such as database credentials and encryption keys. Successful exploitation leads to arbitrary host command execution with the privileges of the backend service user, severely compromising system integrity.

## Attack Chain

1. An authenticated user gains access to the Heym workflow authoring interface.
2. The attacker crafts a malicious workflow using the custom Python tool executor.
3. The workflow exploits Python introspection techniques to access the unrestricted `__import__` function.
4. Using the recovered `__import__` function, the attacker imports restricted modules like `os` or `subprocess`.
5. The attacker uses the imported modules to access inherited backend environment variables.
6. The attacker extracts sensitive data like database credentials or encryption keys from environment variables.
7. The attacker crafts an arbitrary OS command using the `os` or `subprocess` modules.
8. The malicious workflow executes the arbitrary OS command on the host, running as the backend service user.

## Impact

Successful exploitation of this sandbox escape vulnerability (CVE-2026-45227) in Heym allows attackers to execute arbitrary commands on the host system as the backend service user. This can lead to complete system compromise, including data theft, service disruption, and unauthorized access to sensitive information, including database credentials and encryption keys. The vulnerability affects all Heym deployments prior to version 0.0.21.

## Recommendation

*   Upgrade Heym to version 0.0.21 or later to patch CVE-2026-45227.
*   Deploy the Sigma rule "Detect Heym Sandbox Escape Attempt via Import" to monitor for attempts to import restricted modules within the Python tool executor.
*   Review and restrict access to the Heym workflow authoring interface to minimize the attack surface.
