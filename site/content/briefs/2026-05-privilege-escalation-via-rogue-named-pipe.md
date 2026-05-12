---
title: Privilege Escalation via Rogue Named Pipe Impersonation
slug: 2026-05-privilege-escalation-via-rogue-named-pipe
description: An adversary may attempt privilege escalation by masquerading as a known named pipe and manipulating a privileged process to connect to it on Windows systems.
date: "2026-05-12T19:11:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - named-pipe
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1134
    technique_name: Access Token Manipulation
references:
  - https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
  - https://github.com/zcgonvh/EfsPotato
  - https://twitter.com/SBousseaden/status/1429530155291193354
rules:
  - title: Detect Rogue Named Pipe Creation
    description: Detects the creation of named pipes with suspicious paths, often used in privilege escalation attacks like PrintSpoofer or EfsPotato.  Looks for `\pipe\` embedded in the file name.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1134.001
    data_sources:
      - file_event
      - windows
  - title: Detect Potential Pipe Hijacking via Creation Event
    description: Detects creation of named pipes that impersonate services, looking for creation events with 'Pipe' in the name.
    platform: sigma
    severity: low
    tactics:
      - privilege_escalation
    techniques:
      - T1134.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The threat involves an adversary attempting to escalate privileges on a Windows system by creating a rogue named pipe. The attacker masquerades the pipe as a legitimate one, tricking a privileged process into connecting to it. This technique is often employed to abuse impersonation privileges, as seen in tools like PrintSpoofer and EfsPotato. By creating a named pipe with a manipulated path (e.g., including `\\pipe\\` after a path segment that resembles a service/RPC pipe), attackers can intercept and manipulate communication intended for the legitimate service. This can lead to unauthorized command execution or access to sensitive resources with elevated privileges. Detection focuses on identifying suspicious named pipe creations, analyzing the creator process, monitoring client connections, and tracking follow-on activities to determine the likelihood of a successful privilege escalation.

## Attack Chain

1.  The attacker gains initial access to the target system through some vector.
2.  The attacker identifies a privileged process that communicates via named pipes.
3.  The attacker creates a rogue named pipe using `CreateNamedPipe` API. The pipe path is crafted to resemble a legitimate service's pipe, possibly embedding `\\pipe\\` after another path segment.
4.  The privileged process connects to the rogue named pipe. The attacker uses techniques to coerce the privileged process to connect to their rogue pipe.
5.  The attacker impersonates the privileged client. After the privileged process connects, the attacker's process impersonates the security context of the client.
6.  The attacker executes commands or accesses resources with the impersonated privileges.
7.  The attacker gains elevated access to the system.
8.  The attacker persists or expands their access.

## Impact

Successful exploitation allows the attacker to execute arbitrary commands with elevated privileges, potentially gaining full control of the system. This can lead to data theft, system compromise, or the deployment of further malicious payloads. The attack can potentially affect any Windows system where privileged processes communicate via named pipes. The number of affected systems depends on the scope and effectiveness of the attacker's initial access and lateral movement techniques.

## Recommendation

*   Enable Sysmon process creation and file creation logging to capture named pipe creation events (as described in the rule setup instructions: https://ela.st/sysmon-event-pipe-setup).
*   Deploy the Sigma rule "Privilege Escalation via Rogue Named Pipe Impersonation" to your SIEM and tune false positives based on legitimate local IPC products.
*   Investigate any alerts triggered by the Sigma rule, focusing on the rogue pipe path (`file.name`), creator process (`process.executable`), and any privileged clients connecting to the pipe.
