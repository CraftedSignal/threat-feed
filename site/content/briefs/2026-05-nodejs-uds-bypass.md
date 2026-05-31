---
title: Node.js Permission Model Bypass via Unix Domain Sockets (CVE-2026-21711)
slug: 2026-05-nodejs-uds-bypass
description: CVE-2026-21711 allows code running under the Node.js permission model without network access to create and expose local IPC endpoints via Unix Domain Sockets, bypassing intended network restrictions and enabling inter-process communication.
date: "2026-05-31T07:41:19Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - nodejs
  - permission model
  - uds
  - unix domain socket
  - ipc
  - cve-2026-21711
vendors:
  - Microsoft
  - Node.js
products:
  - Node.js 25.x
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-21711
    cvss: 5.3
    epss: 4e-05
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-21711
rules:
  - title: Detect CVE-2026-21711 - Node.js Process with Permission Model and UDS
    description: Detects Node.js processes running with the `--permission` flag that may attempt to exploit CVE-2026-21711 by creating or listening on Unix Domain Sockets.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
  - title: Detect CVE-2026-21711 - Node.js Process with Permission Model and UDS (macOS)
    description: Detects Node.js processes running with the `--permission` flag on macOS that may attempt to exploit CVE-2026-21711 by creating or listening on Unix Domain Sockets.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - macos
rules_count: 2
---

CVE-2026-21711 is a vulnerability in Node.js version 25.x related to the experimental permission model. Specifically, it involves a bypass of network restrictions when using Unix Domain Sockets (UDS). The vulnerability occurs because the permission model's network enforcement mechanisms do not properly apply to UDS server operations. This means that code running with the `--permission` flag, but specifically without `--allow-net` (intended to restrict network access), can still create and expose local Inter-Process Communication (IPC) endpoints through UDS. This enables unauthorized communication with other processes on the same host, effectively circumventing the intended network isolation. This flaw is significant for environments relying on the Node.js permission model to isolate applications and prevent them from accessing network resources.

## Attack Chain

1.  An attacker deploys a Node.js application using Node.js 25.x with the `--permission` flag and intentionally omits the `--allow-net` flag to restrict network access.
2.  The application leverages the `net` module or a similar mechanism to create a Unix Domain Socket server. This operation should, in theory, be blocked by the permission model due to the missing `--allow-net` flag, but due to the vulnerability, the UDS server is created successfully.
3.  The attacker specifies a path for the UDS that allows other processes on the system to connect to it.
4.  A separate, possibly malicious, process on the same host connects to the created UDS. This process could be under the attacker's control or a compromised service.
5.  The attacker's application and the connecting process establish a communication channel over the UDS.
6.  The attacker uses this channel to send commands, data, or other instructions between the two processes, bypassing the intended network restrictions.
7.  The receiving process executes the commands or processes the data received, potentially leading to privilege escalation, data leakage, or other malicious activities.
8.  The attacker achieves their objective, such as gaining unauthorized access to system resources or compromising the integrity of the receiving process.

## Impact

Successful exploitation of CVE-2026-21711 can lead to a bypass of intended network isolation in Node.js applications. This may allow unauthorized processes to communicate with and potentially control isolated applications, leading to privilege escalation, data leakage, or other forms of compromise. The vulnerability affects Node.js 25.x processes utilizing the permission model. The number of affected installations is unknown, but the impact is potentially significant for environments relying on the permission model to restrict network access and isolate applications.

## Recommendation

*   Upgrade to a patched version of Node.js that addresses CVE-2026-21711 once available.
*   Deploy the Sigma rules provided below to detect potential exploitation attempts within your environment, focusing on process creation events when the `--permission` flag is enabled.
*   Monitor Node.js processes for suspicious UDS creation and connection activity using the `network_connection` log source.
*   Review and harden the permission configurations of Node.js applications to prevent unintended access to sensitive resources.
