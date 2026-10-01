---
title: Remote Code Execution in TigerGraph Community Edition via Default Credentials
slug: 2026-10-tigergraph-rce
description: TigerGraph Community Edition 4.2.4 contains a remote code execution chain initiated by hard-coded default credentials, enabling an arbitrary file write that allows for SSH key injection.
date: "2026-10-01T15:12:26Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
tags:
  - remote-code-execution
  - default-credentials
  - privilege-escalation
vendors:
  - TigerGraph
products:
  - TigerGraph Community Edition (4.2.4)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: The GUI administration port (14240) accepts the hard-coded credentials tigergraph:tigergraph
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Directing that write at /home/tigergraph/.ssh/authorized_keys plants an attacker public key
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1133
    technique_name: External Remote Services
    evidence: SSH logon as tigergraph@<target> then yields arbitrary command execution.
    confidence_band: high
rules:
  - title: Detect TigerGraph REST++ Unauthenticated File Write
    description: Detects exploitation attempts against the REST++ interface to trigger arbitrary file writes by monitoring for POST/GET requests to known query endpoints that include file path parameters.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1133
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Update default credentials for the TigerGraph GUI
      owner: IT Operations
      due: 24h
      evidence: Source identifies hard-coded credentials (CWE-798) as the primary entry point
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to TigerGraph management ports 14240, 9000, and 22
      owner: IT Operations
      addresses: CWE-306, CWE-798
      evidence: Exploit relies on reachability of these ports
---

TigerGraph Community Edition 4.2.4 is susceptible to a full remote code execution chain due to multiple architectural security flaws. The vulnerability begins with the use of hard-coded default credentials (tigergraph:tigergraph) on the GUI administration port (14240), which lacks enforcement for password rotation. An attacker who authenticates can access the GUI's reverse-proxy to the GSQL service on port 8123 to install a malicious query capable of writing arbitrary files to the underlying Linux host. Because the REST++ interface on port 9000 fails to authenticate requests, this file-write primitive can be triggered by unauthenticated remote users. By targeting the '/home/tigergraph/.ssh/authorized_keys' file, an attacker can append a controlled public key, subsequently gaining persistent shell access as the 'tigergraph' OS user via SSH.

## Attack Chain

1. Attacker authenticates to the TigerGraph GUI on port 14240 using the default hard-coded credentials 'tigergraph:tigergraph'.
2. Attacker leverages the GUI's proxy to the internal GSQL service (port 8123) to install a custom GSQL query, defined with a FILE parameter that provides an unrestricted arbitrary file write primitive.
3. Attacker triggers the newly installed GSQL query via the REST++ interface on port 9000, which operates without requiring authentication.
4. Attacker submits a request to the REST++ endpoint, specifying the destination path as '/home/tigergraph/.ssh/authorized_keys'.
5. The server writes the attacker-supplied public key into the 'authorized_keys' file on the host filesystem.
6. Attacker initiates an SSH connection to port 22 of the target, authenticating using the private key corresponding to the public key injected in the previous step.
7. Attacker successfully gains an interactive shell session as the 'tigergraph' user, enabling further lateral movement or data exfiltration.

## Impact

Successful exploitation allows an unauthenticated remote attacker to gain persistent unauthorized access to the host operating system with the privileges of the 'tigergraph' service account (UID 1001). This impact includes complete control over the TigerGraph database environment, the ability to read or modify sensitive database information, and the potential for lateral movement within the network from the compromised host.

## Recommendation

* Immediately change the default 'tigergraph' administrative password on all exposed instances.
* Restrict network access to the administration GUI (port 14240), the REST++ interface (port 9000), and the SSH port (22) to authorized management subnets only.
* Review the directory permissions for the '/home/tigergraph/.ssh/' directory to ensure only the owner can modify 'authorized_keys'.
* Monitor access logs on port 14240 for credential-based logins and port 9000 for unexpected REST++ query executions.
* Disable SSH public key authentication for the 'tigergraph' user if it is not explicitly required for administrative operations.
