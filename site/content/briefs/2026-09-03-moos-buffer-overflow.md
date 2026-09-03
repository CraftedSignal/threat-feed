---
title: Buffer Overflow Vulnerability in MOOS ui-moos
slug: 2026-09-03-moos-buffer-overflow
description: The ui-moos component is vulnerable to a buffer overflow in ScopeTabPane.cpp and ScopeGrid.cpp, potentially allowing arbitrary code execution when processing crafted MOOS identifiers.
date: "2026-09-03T23:29:30Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:moos:ui_moos:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - buffer-overflow
vendors:
  - MOOS
products:
  - ui-moos (<= 50b9c6c)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1210
    technique_name: Exploitation of Remote Services
    evidence: Attackers can supply arbitrarily long MOOS identifiers that overflow the buffers when an operator selects process list entries or pokes variables, enabling code execution.
    confidence_band: high
cves:
  - id: CVE-2026-85452
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85452
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Review code or vendor communication to determine if the instance uses commit 50b9c6c or earlier.
      owner: IT Operations
      due: 48h
  mitigation_plan:
    - priority: immediate
      action: Update ui-moos to a version post-50b9c6c that implements bounds checking.
      owner: IT Operations
      addresses: CVE-2026-85452
---

The MOOS (Mission Oriented Operating Suite) ui-moos component, specifically versions through commit 50b9c6c, contains a critical buffer overflow vulnerability within ScopeTabPane.cpp and ScopeGrid.cpp. The vulnerability arises from the use of the sprintf function to format client and variable names into fixed 1024-byte buffers without appropriate length validation. An attacker capable of interacting with the application can supply arbitrarily long MOOS identifiers. When an operator performs actions such as selecting entries from the process list or poking variables, the application attempts to write these overly large strings into the insufficient buffers, triggering a memory corruption event. This vulnerability poses a significant risk to the integrity and availability of the MOOS environment, as successful exploitation could lead to arbitrary code execution on systems running the affected ui-moos component.

## Impact

Successful exploitation of CVE-2026-85452 allows an attacker to achieve code execution within the context of the user running the ui-moos application. This could result in unauthorized system access, data exfiltration, or total compromise of the affected workstation. Given that MOOS is typically used in robotics, marine, and autonomous systems, the operational impact of such a compromise could involve the loss of control over autonomous vehicles or failure of critical mission software.

## Recommendation

Prioritize updating the ui-moos component to a version beyond commit 50b9c6c. Since no official patch release version is specified, verify the fix via source code analysis of the commit history to ensure the sprintf usage has been replaced with safer functions like snprintf. In environments where immediate patching is not possible, implement network segmentation and strict access controls to limit the ability of unauthorized entities to send MOOS identifier packets or interact with the ui-moos process list features.
