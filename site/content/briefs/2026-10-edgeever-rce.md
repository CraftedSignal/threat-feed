---
title: Remote Code Execution in EdgeEver Desktop via IPC Handler
slug: 2026-10-edgeever-rce
description: EdgeEver Desktop versions 1.92.0 through 1.112.0 contain a remote code execution vulnerability in the desktop:acp-probe IPC handler that allows arbitrary command execution via an insecure probeAcpAdapter function.
date: "2026-10-12T22:42:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:edgeever:edgeever_desktop:*:*:*:*:*:*:*:*
vendors:
  - EdgeEver
products:
  - EdgeEver Desktop (1.92.0-1.112.0)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers with script execution in a renderer... can call probeAcpAdapter to launch local executables with the user's privileges.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The component... spawns a caller-supplied input.path executable.
    confidence_band: high
cves:
  - id: CVE-2026-109556
    cvss: 8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109556
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade all instances of EdgeEver Desktop to a version released after 1.112.0.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-109556 advisory.
  mitigation_plan:
    - priority: immediate
      action: Upgrade EdgeEver Desktop beyond version 1.112.0.
      owner: IT Operations
      addresses: CVE-2026-109556
      evidence: Source advisory
---

EdgeEver Desktop versions 1.92.0 through 1.112.0 are vulnerable to remote code execution (RCE) via the desktop:acp-probe inter-process communication (IPC) handler. The vulnerability stems from a failure to perform adequate sender verification in the IPC handler, which subsequently facilitates the execution of a caller-supplied executable path. An attacker who gains control over the renderer process, potentially through stored cross-site scripting (XSS) in components like template-preview or drag-preview, can invoke the probeAcpAdapter function to execute arbitrary local binaries. Successful exploitation allows an attacker to execute code with the full privileges of the user running the EdgeEver Desktop application. This vulnerability is assigned CVE-2026-109556 and represents a significant risk for desktop environments where the application is deployed.

## Impact

Successful exploitation allows for arbitrary code execution with the user's permissions. This may lead to full system compromise, data theft, or persistence on the affected host, impacting users of EdgeEver Desktop versions 1.92.0 through 1.112.0 across Windows, macOS, and Linux platforms.

## Recommendation

* Patch EdgeEver Desktop to a version beyond 1.112.0 immediately.
* Audit applications utilizing Electron or similar frameworks for insecure IPC handler configurations and lack of input validation on executable paths.
* Monitor for unexpected process spawns originating from the EdgeEver Desktop primary application process.
