---
title: Local Privilege Escalation in IBM Informix Dynamic Server
slug: 2026-08-informix-lpe
description: A local privilege escalation vulnerability in the oninit setuid-root utility of IBM Informix Dynamic Server 14.10 and 15.0 allows local authenticated users to gain elevated system privileges.
date: "2026-08-12T22:52:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
  - local-access
vendors:
  - IBM
products:
  - Informix Dynamic Server (14.10)
  - Informix Dynamic Server (15.0)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: IBM Informix Dynamic Server 14.10, and 15.0 contain a local privilege escalation vulnerability in the oninit setuid-root utility.
    confidence_band: high
cves:
  - id: CVE-2026-13367
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-13367
  - https://www.ibm.com/support/pages/node/7282829
---

IBM has identified a local privilege escalation vulnerability, tracked as CVE-2026-13367, affecting Informix Dynamic Server versions 14.10 and 15.0. The vulnerability resides within the 'oninit' utility, which is configured with the setuid-root bit. Due to improper access control (CWE-284), a low-privileged local attacker can exploit this utility to execute arbitrary code or commands with root privileges. This vulnerability poses a significant risk to the integrity and confidentiality of the host operating system, as it allows for a complete system compromise from a restricted user account. Defenders should prioritize patching or applying vendor-recommended mitigations to the 'oninit' utility binary.

## Attack Chain

1. Attacker establishes low-privileged access to the host server where IBM Informix is installed.
2. Attacker locates the 'oninit' utility, typically within the Informix binary directory, and confirms the setuid-root permission bit is active.
3. Attacker identifies inputs or environment variables that influence the execution flow of the 'oninit' process.
4. Attacker crafts a malicious payload or environment configuration to trigger the improper access control vulnerability.
5. Attacker executes the manipulated 'oninit' utility as a low-privileged user.
6. The vulnerability in 'oninit' fails to drop privileges or improperly handles user input, leading to the execution of attacker-controlled commands with elevated root context.
7. Attacker successfully gains root-level command execution on the host system.

## Impact

Successful exploitation allows a local user to escalate privileges to root on the Informix host system. This may result in full system compromise, unauthorized access to sensitive database files, persistence via rootkit installation, or destruction of system-level configurations. IBM has confirmed the vulnerability impacts Informix Dynamic Server 14.10 and 15.0.

## Recommendation

* Apply the official patch provided by IBM at https://www.ibm.com/support/pages/node/7282829.
* Audit file permissions on the 'oninit' binary to ensure only necessary users have execution rights.
* Enable process monitoring on the 'oninit' binary to detect unusual executions or anomalous command-line arguments that may indicate exploitation attempts.
