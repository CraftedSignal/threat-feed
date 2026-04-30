---
title: 'PhantomRPC: Windows RPC Privilege Escalation Vulnerability'
slug: 2026-04-phantom-rpc-privesc
description: A vulnerability in Windows RPC architecture allows an attacker to create a fake RPC server and escalate their privileges to SYSTEM level, leveraging processes with impersonation privileges.
date: "2026-04-24T08:00:12Z"
type: coverage
types:
  - coverage
severities:
  - critical
tags:
  - privilege-escalation
  - rpc
  - windows
vendors:
  - Microsoft
products:
  - Windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
references:
  - https://securelist.com/phantomrpc-rpc-vulnerability/119428/
rules:
  - title: Detect Suspicious ALPC Port Creation
    description: Detects the creation of ALPC ports by unusual processes, potentially indicating an attempt to establish a malicious RPC server.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
  - title: Detect RpcImpersonateClient API Call from Unusual Process
    description: Detects calls to the RpcImpersonateClient API from processes that do not typically perform impersonation.
    platform: sigma
    severity: critical
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

Kaspersky researchers discovered a critical vulnerability in the Windows Remote Procedure Call (RPC) architecture, dubbed PhantomRPC, that enables local privilege escalation. The flaw allows an attacker to create a rogue RPC server and, by exploiting existing processes with impersonation privileges (such as those running as Local Service or Network Service), elevate their own permissions to SYSTEM. The vulnerability resides in the architectural design of RPC itself, making it potentially exploitable across all Windows versions. The researcher has demonstrated five different exploitation paths escalating privileges from various local or network service contexts. This issue has been disclosed to Microsoft, but a patch has not yet been released. Due to the fundamental nature of the vulnerability, the number of potential attack vectors is effectively unlimited.

## Attack Chain

1. The attacker gains initial access to the system with low privileges.
2. The attacker identifies a service running with `SeImpersonatePrivilege`, such as Local Service or Network Service.
3. The attacker crafts a malicious RPC server application designed to exploit the PhantomRPC vulnerability.
4. The attacker triggers a connection from the target service (e.g., Group Policy Client service) to the attacker's malicious RPC server via ALPC.
5. The malicious RPC server uses `RpcImpersonateClient` API to impersonate the SYSTEM account.
6. The attacker's malicious RPC server executes code within the security context of the SYSTEM account.
7. The attacker leverages the elevated privileges to perform arbitrary actions, such as installing malware, creating new accounts, or accessing sensitive data.

## Impact

Successful exploitation of PhantomRPC allows a low-privileged attacker to gain complete control over the affected system by escalating privileges to SYSTEM. This can lead to complete system compromise, including data theft, malware installation, and denial of service. The vulnerability affects all Windows versions and given the number of potential attack vectors, it poses a significant risk to a large number of systems. While the exact number of potential victims remains unknown, the widespread use of RPC in Windows makes this a highly critical issue.

## Recommendation

*   Monitor for the creation of suspicious ALPC ports, especially those targeting services with `SeImpersonatePrivilege`. Use the Sigma rule `Detect Suspicious ALPC Port Creation` to identify potential exploitation attempts.
*   Monitor for processes calling the `RpcImpersonateClient` API, especially those originating from unusual or untrusted processes. Use the Sigma rule `Detect RpcImpersonateClient API Call from Unusual Process` to identify potential exploitation attempts.
*   Restrict access to services with `SeImpersonatePrivilege` where possible, limiting the potential attack surface.
