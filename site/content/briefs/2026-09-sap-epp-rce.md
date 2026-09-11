---
title: Remote Code Execution Vulnerability in SAP Extended Passport Processing
slug: 2026-09-sap-epp-rce
description: A critical unauthenticated remote code execution vulnerability in the SAP Extended Passport (EPP) kernel component allows attackers to execute arbitrary system commands via RFC or HTTP communication layers.
date: "2026-09-11T00:57:44Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - sap
  - rce
  - kernel
  - vulnerability
vendors:
  - SAP
products:
  - SAP Kernel
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The bug is remotely exploitable without authentication and exists by default in a range of SAP components.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Successful exploitation of this vulnerability may allow a remote attacker to run arbitrary operating system commands on the SAP host with SAP administrative privileges.
    confidence_band: high
references:
  - https://www.cisecurity.org/advisory/a-vulnerability-in-sap-extended-passport-epp-processing-could-allow-for-remote-code-execution_2026-092
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all internet-facing SAP infrastructure.
      owner: IT Operations
      due: 24h
      evidence: Source identifies vulnerability as remotely exploitable via SAP GUI and RFC.
  mitigation_plan:
    - priority: immediate
      action: Monitor vendor security portal for SAP kernel patches addressing EPP processing.
      owner: IT Operations
      addresses: SAP Kernel vulnerability
      evidence: Advisory indicates vulnerability exists in core SAP kernel code.
---

Researchers have identified a critical vulnerability within SAP Extended Passport (EPP) processing, a core kernel mechanism utilized across the SAP ecosystem for tracing and monitoring end-to-end communication. EPP data structures are generated automatically upon the initiation of user sessions and traverse distributed landscapes via communication protocols including RFC (Remote Function Call) and HTTP. Because this EPP processing logic is embedded within the SAP Kernel, the vulnerability is accessible to unauthenticated attackers through the SAP GUI layer or via inter-system RFC links. This allows for remote exploitation without prior authentication. Successful execution leads to the compromise of the underlying SAP host, as the attacker gains the ability to run arbitrary operating system commands with SAP administrative privileges. This vulnerability affects a broad range of SAP components and poses a significant risk of total data and process compromise for organizations running affected SAP environments.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated remote attacker to achieve full system compromise. By gaining the ability to execute arbitrary OS commands with administrative privileges, an attacker can exfiltrate sensitive business data, manipulate core enterprise processes, and pivot deeper into the target organization's internal network. This threat is particularly critical due to the ubiquitous nature of the affected SAP Kernel code across both SAP and non-SAP interconnected landscapes.

## Recommendation

Prioritize the identification of internet-facing SAP components. Monitor SAP logs for anomalous RFC and HTTP traffic patterns originating from unauthorized or external network ranges. Engage with SAP support to obtain and apply the necessary kernel patches to address the EPP processing vulnerability.
