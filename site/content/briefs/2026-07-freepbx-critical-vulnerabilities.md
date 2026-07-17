---
title: FreePBX Modules Vulnerable to Unauthenticated RCE and SQL Injection
slug: 2026-07-freepbx-critical-vulnerabilities
description: Multiple critical vulnerabilities have been identified in FreePBX modules, including unauthenticated remote code execution (RCE) in the UCP module, unauthenticated SQL injection in the missedcall module leading to administrator takeover, authenticated command injection in the TTS module, and authenticated RCE in the music module. These flaws affect specific versions of these modules across FreePBX 16 and 17, allowing attackers to execute arbitrary commands, bypass authentication, and gain administrative control.
date: "2026-07-17T14:30:21Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - freepbx
  - rce
  - sql-injection
  - command-injection
  - web-vulnerability
  - asterisk
vendors:
  - FreePBX
products:
  - FreePBX Security-Reporting ucp (FreePBX 17)
  - FreePBX Security-Reporting missedcall (FreePBX 16)
  - FreePBX Security-Reporting missedcall (FreePBX 17)
  - FreePBX Security-Reporting tts (FreePBX 17)
  - FreePBX Security-Reporting tts (FreePBX 16)
  - FreePBX Security-Reporting music (FreePBX 17)
  - FreePBX Security-Reporting framework (FreePBX 16)
  - FreePBX Security-Reporting framework (FreePBX 17)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated remote code execution in FreePBX UCP via socket.io namespace auth bypass and AMI action injection; Unauthenticated SQL injection in FreePBX missedcall via inbound Caller ID name leads to administrator takeover
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Unauthenticated remote code execution in FreePBX UCP via socket.io namespace auth bypass and AMI action injection
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Unauthenticated SQL injection in FreePBX missedcall via inbound Caller ID name leads to administrator takeover
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: Authenticated Framework AUTHTYPE Can Be Restored From a Crafted Backup
    confidence_band: med
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Unauthenticated SQL injection in FreePBX missedcall via inbound Caller ID name leads to administrator takeover
    confidence_band: high
references:
  - https://cyber.gc.ca/en/alerts-advisories/freepbx-security-advisory-av26-711
  - https://github.com/FreePBX/security-reporting/security/advisories/GHSA-37j8-fhxx-9vhp
  - https://github.com/FreePBX/security-reporting/security/advisories/GHSA-g27h-xf3q-h3rm
  - https://github.com/FreePBX/security-reporting/security/advisories/GHSA-hg3v-m857-mvw9
  - https://github.com/FreePBX/security-reporting/security/advisories/GHSA-p97w-rq48-p8q2
  - https://github.com/FreePBX/security-reporting/security/advisories/GHSA-f6hc-rqxg-ch86
  - https://github.com/FreePBX/security-reporting/security/advisories?state=published
rules:
  - title: Detects GHSA-37j8-fhxx-9vhp Exploitation - Unauthenticated FreePBX UCP RCE Attempt
    description: Detects attempts to exploit unauthenticated remote code execution (RCE) in FreePBX UCP via socket.io namespace auth bypass and AMI action injection by looking for common command injection patterns in HTTP requests to UCP or socket.io related paths.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
      - T1190
    data_sources:
      - webserver
  - title: Detects GHSA-g27h-xf3q-h3rm Exploitation - Unauthenticated FreePBX Missedcall SQLi Attempt
    description: Detects attempts to exploit unauthenticated SQL injection in FreePBX missedcall module via inbound Caller ID name, leading to administrator takeover. Looks for common SQL injection payloads in HTTP requests to missedcall related paths.
    platform: sigma
    severity: high
    tactics:
      - initial_access
      - privilege_escalation
    techniques:
      - T1059.008
      - T1190
    data_sources:
      - webserver
rules_count: 2
---

On July 17, 2026, the Canadian Centre for Cyber Security (CCCS) issued an advisory highlighting several critical vulnerabilities within various FreePBX modules. These security flaws impact FreePBX versions 16 and 17, with some allowing for unauthenticated remote code execution (RCE) and unauthenticated SQL injection leading to administrator takeover. Specifically, the FreePBX Security-Reporting ucp module is vulnerable to unauthenticated RCE (GHSA-37j8-fhxx-9vhp) in versions prior to 17.0.9. The FreePBX Security-Reporting missedcall module is susceptible to unauthenticated SQL injection (GHSA-g27h-xf3q-h3rm) in versions prior to 16.0.11 and 17.0.6. Additionally, authenticated command injection (GHSA-hg3v-m857-mvw9) and RCE (GHSA-p97w-rq48-p8q2) affect the tts and music modules respectively, and an authenticated framework vulnerability (GHSA-f6hc-rqxg-ch86) allows AUTHTYPE restoration from crafted backups. These vulnerabilities pose a significant risk, enabling attackers to compromise the FreePBX system, execute arbitrary commands, and gain full administrative control without prior authentication in some cases.

## Attack Chain

1. **Reconnaissance**: An attacker identifies internet-facing FreePBX installations using tools like Shodan or targeted scanning to locate vulnerable instances of FreePBX 16 or 17.
2. **Initial Access (Unauthenticated RCE)**: The attacker crafts and sends a specially malformed HTTP request to the vulnerable FreePBX UCP module (versions prior to 17.0.9), exploiting the `socket.io` namespace authentication bypass and AMI action injection (GHSA-37j8-fhxx-9vhp) to execute arbitrary commands on the FreePBX server.
3. **Initial Access (Unauthenticated SQL Injection)**: Alternatively, the attacker sends a crafted HTTP request to a vulnerable FreePBX missedcall module (versions prior to 16.0.11 or 17.0.6), injecting malicious SQL payloads into the inbound Caller ID name parameter to exploit the SQL injection vulnerability (GHSA-g27h-xf3q-h3rm).
4. **Privilege Escalation**: Successful SQL injection allows the attacker to query or modify the FreePBX database, potentially retrieving or resetting administrative credentials, thereby achieving administrative takeover of the FreePBX system.
5. **Command and Control**: With RCE or administrative access, the attacker establishes a persistent foothold by executing commands to install backdoors, create new administrative users, or modify system configurations.
6. **Impact**: The attacker gains full control over the FreePBX server, compromising call records, sensitive configuration data, and potentially leveraging the system for further network intrusion or telephony fraud.

## Impact

Successful exploitation of these vulnerabilities leads to severe consequences, including full system compromise, data theft, and unauthorized control over the FreePBX communication platform. The unauthenticated nature of the RCE and SQL injection flaws means that attackers can gain initial access without requiring any credentials, significantly increasing the risk. An attacker gaining administrative takeover could lead to the exposure of sensitive call detail records, manipulation of VoIP infrastructure, deployment of malware, or use of the FreePBX system as a launchpad for further attacks within the organization's network. While no specific victim counts are mentioned, the widespread use of FreePBX suggests a broad potential impact across various sectors.

## Recommendation

* Apply the necessary updates for FreePBX Security-Reporting ucp (FreePBX 17) to version 17.0.9 or later.
* Apply the necessary updates for FreePBX Security-Reporting missedcall (FreePBX 16) to version 16.0.11 or later.
* Apply the necessary updates for FreePBX Security-Reporting missedcall (FreePBX 17) to version 17.0.6 or later.
* Apply the necessary updates for FreePBX Security-Reporting tts (FreePBX 17) to version 17.0.6 or later.
* Apply the necessary updates for FreePBX Security-Reporting tts (FreePBX 16) to version 16.0.6 or later.
* Apply the necessary updates for FreePBX Security-Reporting music (FreePBX 17) to version 17.0.7 or later.
* Apply the necessary updates for FreePBX Security-Reporting framework (FreePBX 16) to version 16.0.47 or later.
* Apply the necessary updates for FreePBX Security-Reporting framework (FreePBX 17) to version 17.0.30 or later.
* Deploy the Sigma rules in this brief to your SIEM and tune for your environment to detect attempts to exploit `GHSA-37j8-fhxx-9vhp` and `GHSA-g27h-xf3q-h3rm`.
