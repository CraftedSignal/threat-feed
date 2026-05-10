---
title: NocoBase 2.0.27 VM Sandbox Escape Vulnerability
slug: 2026-05-nocobase-sandbox-escape
description: A local exploit has been published for NocoBase 2.0.27, detailing a VM Sandbox Escape vulnerability, increasing the risk to unpatched systems.
date: "2026-05-07T00:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vm-sandbox-escape
  - local-exploit
  - nocobase
vendors:
  - NocoBase
products:
  - NocoBase 2.0.27
references:
  - https://www.exploit-db.com/exploits/52552
rules:
  - title: Detect Suspicious Process from NocoBase
    description: Detects suspicious processes spawned from NocoBase application directory, potentially indicating a sandbox escape
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect Privilege Escalation from NocoBase
    description: Detects attempts to escalate privileges after a potential sandbox escape from NocoBase.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A public exploit has been released on Exploit-DB targeting NocoBase 2.0.27, a no-code/low-code platform. This exploit demonstrates a VM Sandbox Escape vulnerability, which allows a malicious actor with local access to break out of the NocoBase's virtualized environment. The availability of this exploit (EDB-52552) means that unpatched NocoBase instances are at significant risk of being compromised. Successful exploitation could lead to unauthorized access, data breaches, or complete system takeover. Defenders should prioritize patching or mitigating this vulnerability to prevent potential attacks.

## Attack Chain

Since the exploit is local and the details of the vulnerability are not provided, the following attack chain is generalized based on common sandbox escape techniques:

1. Attacker gains initial local access to the NocoBase server or application instance. This could be achieved through compromised credentials, social engineering, or by exploiting another vulnerability.
2. Attacker leverages the published exploit (EDB-52552) to trigger the VM Sandbox Escape vulnerability within NocoBase 2.0.27.
3. The exploit code manipulates the virtualized environment to gain unauthorized access to the host operating system.
4. Attacker executes arbitrary code on the host operating system outside the confines of the NocoBase sandbox.
5. Attacker escalates privileges to gain administrator or root access on the host system.
6. Attacker installs persistence mechanisms (e.g., backdoors, scheduled tasks) to maintain access to the compromised system.
7. Attacker performs reconnaissance to identify sensitive data and internal resources.
8. Attacker exfiltrates sensitive data or launches further attacks against internal systems.

## Impact

Successful exploitation of the VM Sandbox Escape vulnerability in NocoBase 2.0.27 could allow an attacker to gain complete control over the underlying server. This could lead to data breaches, unauthorized access to sensitive information, disruption of services, and potential lateral movement within the network. The impact is significant due to the potential for full system compromise from a local vulnerability.

## Recommendation

*   Apply available patches or upgrades to NocoBase to address the VM Sandbox Escape vulnerability.
*   Monitor process creation events for unusual processes originating from the NocoBase application directory (see Sigma rule `Detect Suspicious Process from NocoBase`).
*   Implement strict access controls to limit local access to the NocoBase server (e.g., principle of least privilege).
*   Review NocoBase's configuration settings to ensure the virtualized environment is securely configured.
*   Deploy the Sigma rule `Detect Privilege Escalation from NocoBase` to your SIEM to detect attempts to escalate privileges after a potential sandbox escape.
