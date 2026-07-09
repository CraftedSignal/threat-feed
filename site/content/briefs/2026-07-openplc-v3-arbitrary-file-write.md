---
title: OpenPLC v3 Arbitrary File Write Leads to Native Code Execution (CVE-2026-14480)
slug: 2026-07-openplc-v3-arbitrary-file-write
description: An authenticated arbitrary file write vulnerability (CVE-2026-14480) in OpenPLC v3's legacy web UI program-upload workflow allows attackers to write arbitrary files, escalating to arbitrary native code execution as the OpenPLC runtime user when an operator triggers program compilation.
date: "2026-07-09T15:57:54Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ics
  - scada
  - vulnerability
  - rce
  - authenticated-rce
  - file-write
  - cwe-73
vendors:
  - OpenPLC
products:
  - OpenPLC v3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An authenticated arbitrary file write vulnerability ... in the legacy web UI program‑upload workflow.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: escalate this into arbitrary native code execution through the normal OpenPLC program compilation process
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: arbitrary native code execution through the normal OpenPLC program compilation process
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-190-01
  - https://www.cve.org/CVERecord?id=CVE-2026-14480
---

OpenPLC v3 is affected by CVE-2026-14480, an authenticated arbitrary file write vulnerability (CWE-73) within its legacy web UI program-upload workflow. This critical flaw allows an authenticated attacker to manipulate the `prog_file` parameter, typically used for specifying a filename, to instead provide a path traversal sequence. The system fails to validate or restrict this path, enabling the attacker to write arbitrary files to any location writable by the OpenPLC webserver process. This arbitrary file write can be escalated to arbitrary native code execution; by injecting a malicious C++ file into the OpenPLC Runtime Core directory, an attacker can ensure their code is automatically compiled and executed as part of the normal OpenPLC program compilation process when an operator starts the runtime. This vulnerability poses a significant risk to critical infrastructure sectors including Critical Manufacturing, Energy, Transportation Systems, and Water and Wastewater, with deployments worldwide. OpenPLC v3 is now end-of-life and will not receive patches.

## Attack Chain

1. An authenticated attacker logs into the OpenPLC v3 web UI, typically using legitimate or compromised credentials.
2. The attacker accesses the legacy program-upload workflow, which handles PLC program submissions.
3. The attacker crafts a malicious HTTP request, sending a crafted `prog_file` parameter containing a path traversal sequence (e.g., `../../../OpenPLC_Runtime_Core/malicious.cpp`).
4. Due to insufficient path validation, the OpenPLC webserver process writes the attacker-controlled malicious C++ file (e.g., `malicious.cpp`) to the specified arbitrary location within the OpenPLC Runtime Core directory.
5. At a later point, a legitimate operator initiates a normal program compilation and runtime start operation within the OpenPLC environment.
6. During this standard compilation process, the attacker's previously written `malicious.cpp` file is automatically included, compiled, and linked into the OpenPLC runtime binary.
7. The newly compiled OpenPLC runtime binary, now containing the attacker's embedded code, is executed.
8. This execution leads to arbitrary native code execution on the OpenPLC server, with the privileges of the OpenPLC runtime user, potentially compromising the control system.

## Impact

Successful exploitation of CVE-2026-14480 allows an authenticated attacker to achieve arbitrary native code execution as the OpenPLC runtime user. This grants the attacker significant control over the affected system, enabling them to disrupt operations, manipulate processes, or exfiltrate sensitive data. Given OpenPLC's deployment in critical infrastructure sectors such as Critical Manufacturing, Energy, Transportation Systems, and Water and Wastewater, the impact could range from operational disruption and safety hazards to widespread system compromise and economic damage. OpenPLC v3 being end-of-life means that affected organizations are left vulnerable unless they upgrade to v4.

## Recommendation

* Upgrade all OpenPLC v3 instances to OpenPLC v4 immediately, as recommended by OpenPLC, due to OpenPLC v3 being end-of-life and no longer receiving security updates for CVE-2026-14480.
* Minimize network exposure for all control system devices and/or systems, ensuring they are not accessible from the internet, as highlighted in the CISA recommendations.
* Locate control system networks and remote devices behind firewalls and isolate them from business networks, as advised by CISA for CVE-2026-14480.
* When remote access is required, use more secure methods, such as Virtual Private Networks (VPNs), and ensure VPNs are updated to the most current version available.
