---
title: Erlang/OTP Information Disclosure Vulnerability
slug: 2026-05-erlang-info-disclosure
description: A remote, authenticated attacker can exploit an unspecified vulnerability in Erlang/OTP to disclose sensitive information.
date: "2026-05-07T09:32:29Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - information-disclosure
  - vulnerability
  - erlang
vendors:
  - Erlang
products:
  - Erlang/OTP
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Use of OS Credentials
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-0473
rules:
  - title: Detect Suspicious Erlang Authentication Patterns
    description: Detects unusual Erlang authentication patterns that may indicate exploitation attempts.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1110
    data_sources:
      - network_connection
      - erlang
  - title: Detect Anomalous Erlang Process Behavior
    description: Detects anomalous Erlang process behavior indicative of unauthorized access or exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
    data_sources:
      - process_creation
      - erlang
rules_count: 2
---

Erlang/OTP is susceptible to an information disclosure vulnerability that can be exploited by a remote, authenticated attacker. The vulnerability resides within an unspecified component of Erlang/OTP. An attacker who successfully authenticates to a system running a vulnerable version of Erlang/OTP can potentially gain access to sensitive data that should otherwise be protected. The specifics of the vulnerability and its exploitation are not detailed, but the potential for unauthorized information access poses a significant risk to the confidentiality of affected systems. This vulnerability impacts systems running Erlang/OTP.

## Attack Chain

1. The attacker gains valid credentials for a user account on a system running Erlang/OTP.
2. The attacker establishes a remote connection to the Erlang/OTP system using the compromised credentials.
3. The attacker interacts with the vulnerable component of Erlang/OTP.
4. Due to the unspecified vulnerability, the system improperly handles the attacker's requests.
5. The attacker is able to bypass intended security controls.
6. Sensitive information, such as configuration data or user data, is exposed to the attacker.
7. The attacker collects the disclosed information.
8. The attacker uses the information for further malicious activities, such as lateral movement or data exfiltration (outside the scope of this advisory).

## Impact

Successful exploitation of this vulnerability allows a remote, authenticated attacker to gain unauthorized access to sensitive information stored or processed by Erlang/OTP. The impact includes potential compromise of user data, exposure of internal configurations, and other confidential data. The extent of the impact depends on the type of information accessible through the vulnerability and the attacker's subsequent actions.

## Recommendation

*   Investigate the Erlang/OTP systems to identify vulnerable components and apply necessary patches or mitigations once available from the vendor.
*   Monitor Erlang/OTP logs for suspicious activity indicative of unauthorized access attempts, focusing on unusual patterns of authenticated requests (see example Sigma rule below).
*   Implement strong authentication mechanisms and regularly review user access privileges to minimize the risk of credential compromise.
