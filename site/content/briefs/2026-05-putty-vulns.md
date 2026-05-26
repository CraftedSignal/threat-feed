---
title: Multiple Vulnerabilities in PuTTY Allow for DoS, Data Manipulation, and Spoofing
slug: 2026-05-putty-vulns
description: A remote, anonymous attacker can exploit multiple vulnerabilities in PuTTY to perform a denial of service attack, manipulate data, and possibly carry out spoofing attacks.
date: "2026-05-26T11:39:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - putty
  - vulnerability
  - denial-of-service
  - spoofing
vendors:
  - PuTTY
products:
  - PuTTY
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1036
    technique_name: Masquerading
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1071.001
    technique_name: 'Application Layer Protocol: Web Protocols'
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-1673
rules:
  - title: Detect Suspicious PuTTY Process Name
    description: Detects PuTTY process names that deviate from the standard 'putty.exe', indicating possible renaming for malicious purposes
    platform: sigma
    severity: low
    tactics:
      - defense_evasion
    techniques:
      - T1036
    data_sources:
      - process_creation
      - windows
  - title: Detect PuTTY connecting to unusual ports
    description: Detects PuTTY connecting to ports other than the standard SSH (22) or Telnet (23), indicating non-standard activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Multiple vulnerabilities have been identified in PuTTY that could be exploited by a remote, anonymous attacker. These vulnerabilities, if successfully exploited, can lead to a denial-of-service condition, manipulation of data, and potentially the execution of spoofing attacks. The advisory does not specify which versions are affected, but defenders should assume all versions are potentially vulnerable until updates are released. Given PuTTY's widespread use for SSH and Telnet connections, these vulnerabilities pose a risk to organizations that rely on it for secure remote access and network management. Successful exploitation could disrupt services, compromise data integrity, or enable attackers to impersonate legitimate users or systems.

## Attack Chain

1.  The attacker identifies a vulnerable PuTTY client or server. The specific vulnerability is not mentioned.
2.  The attacker establishes a connection to the target PuTTY instance. This could be either client or server side, depending on the vulnerable function.
3.  The attacker sends a crafted request or payload to the vulnerable PuTTY component. The specific mechanism varies depending on the vulnerability.
4.  A buffer overflow or other memory corruption issue occurs within PuTTY's code.
5.  The attacker exploits the memory corruption to cause a denial of service by crashing the application.
6.  Alternatively, the attacker manipulates program data to alter the behavior of PuTTY.
7.  The attacker uses the data manipulation to spoof communications.
8.  The attacker gains unauthorized access or disrupts normal operations of the targeted system.

## Impact

Successful exploitation of these vulnerabilities could lead to several negative consequences. A denial-of-service attack could disrupt network services and prevent users from accessing critical systems. Data manipulation could compromise the integrity of sensitive information and lead to incorrect or unauthorized actions. Spoofing attacks could enable attackers to gain unauthorized access to systems or impersonate legitimate users, potentially leading to further compromise. The scope of the impact will depend on the specific vulnerabilities exploited and the targeted systems, affecting potentially thousands of PuTTY users worldwide.

## Recommendation

*   Monitor network traffic for suspicious patterns indicative of exploitation attempts, specifically those targeting SSH and Telnet protocols, using network connection logs.
*   Implement rate limiting on SSH and Telnet connections to mitigate potential denial-of-service attacks.
*   Deploy the Sigma rule `Detect Suspicious PuTTY Process Name` to identify potentially malicious PuTTY processes.
*   Conduct regular security audits of systems running PuTTY to identify and remediate any misconfigurations or vulnerabilities.
