---
title: RustDesk Authorization Bypass via Session Scope Enforcement Failure (CVE-2026-57850)
slug: 2026-07-rustdesk-auth-bypass
description: An authorization vulnerability exists in RustDesk before version 1.4.9 where the server-side fails to properly enforce connection scope for authenticated peers, allowing an attacker, having been granted a limited session type, to inject control messages typically reserved for a full Remote session and gain unauthorized observation and control over the host.
date: "2026-07-10T20:17:46Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - authorization-bypass
  - remote-access
vendors:
  - RustDesk
products:
  - RustDesk < 1.4.9
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: a peer granted a limited session type (FileTransfer, PortForward, ViewCamera, or Terminal) can send control messages and login options reserved for a full Remote session. An authenticated remote peer can exploit this missing scope check to act outside its granted scope, injecting out-of-scope control messages to observe and control the host beyond the permissions it was given.
    confidence_band: high
cves:
  - id: CVE-2026-57850
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-57850
---

CVE-2026-57850 identifies an authorization bypass vulnerability in RustDesk, a popular open-source remote desktop software. Prior to version 1.4.9, the RustDesk server-side component fails to properly enforce the authorized scope of a remote connection session. This design flaw allows an authenticated peer, who has been granted a limited session type such as FileTransfer, PortForward, ViewCamera, or Terminal access, to inject control messages and login options typically reserved for a full remote desktop session. This effectively enables the attacker to circumvent their assigned permissions and gain unauthorized observation and control capabilities over the host system. The vulnerability carries a CVSS v3.1 base score of 8.3 (High severity) and impacts all RustDesk server deployments running versions older than 1.4.9, posing a significant risk for organizations using the software for remote access.

## Attack Chain

1. **Initial Access / Authentication:** An attacker gains authenticated access to a target RustDesk server, receiving a limited session type (e.g., FileTransfer, PortForward, ViewCamera, or Terminal).
2. **Session Scope Bypass Attempt:** The authenticated attacker, leveraging the server's failure to enforce session scope, sends control messages or login options that are typically reserved for a full Remote Desktop session type.
3. **Unauthorized Control Message Injection:** The RustDesk server processes these out-of-scope control messages, despite the attacker's session type not authorizing such actions.
4. **Observation and Control:** The attacker successfully gains unauthorized observation and control capabilities over the host system, bypassing the intended limitations of their initial session.
5. **Privilege Escalation:** By exercising these newly acquired full remote session capabilities, the attacker effectively elevates their privileges beyond what was initially granted for their limited session.
6. **Impact:** The attacker can perform actions that would normally require a full Remote session, such as executing arbitrary commands, accessing sensitive data, or installing further malicious software.

## Impact

Successful exploitation of CVE-2026-57850 allows an authenticated attacker to bypass intended session limitations and gain unauthorized observation and control over the host system. This can lead to significant consequences, including the execution of arbitrary commands, data exfiltration, system compromise, and further lateral movement within an affected network. Organizations relying on RustDesk for remote access, particularly those utilizing limited session types for specific tasks, are at risk of having these restrictions circumvented, leading to a complete compromise of the accessed system. The vulnerability's high CVSS score of 8.3 reflects the severe potential impact on confidentiality, integrity, and availability.

## Recommendation

* **Patch CVE-2026-57850 immediately by upgrading RustDesk to version 1.4.9 or later.** This directly addresses the authorization bypass vulnerability.
* **Implement robust logging and monitoring for RustDesk server activity**, specifically focusing on unexpected control messages or attempts to perform actions outside of an established session's granted scope, as described in the "Attack Chain."
* **Regularly review and audit RustDesk session logs** for any indicators of unauthorized privilege escalation attempts or out-of-scope actions.
