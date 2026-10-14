---
title: Unauthenticated Remote API Access in SmsForwarder
slug: 2026-10-smsforwarder-auth-bypass
description: SmsForwarder through version 3.5.0 contains a missing authentication vulnerability in its embedded AndServer HTTP server, allowing attackers to remotely control the application and access sensitive data.
date: "2026-10-14T16:36:48Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:smsforwarder_project:smsforwarder:*:*:*:*:*:android:*:*
tags:
  - vulnerability
  - mobile
  - authentication-bypass
vendors:
  - SmsForwarder
products:
  - SmsForwarder (<= 3.5.0)
affected_os:
  - Android
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SmsForwarder through 3.5.0 contains a missing authentication vulnerability in its AndServer HTTP server that allows unauthenticated network attackers to invoke remote-control APIs.
    confidence_band: high
cves:
  - id: CVE-2026-110618
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110618
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade SmsForwarder to a version remediating the authentication bypass in AndServer
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-110618 necessitates updating affected software versions
  mitigation_plan:
    - priority: immediate
      action: Restrict network exposure of the SmsForwarder AndServer port
      owner: IT Operations
      addresses: CVE-2026-110618
      evidence: Vulnerability allows unauthenticated network attackers to invoke APIs
---

SmsForwarder through version 3.5.0 is vulnerable to a missing authentication flaw within its embedded AndServer HTTP server component. This vulnerability allows an unauthenticated network-adjacent attacker to reach sensitive remote-control API endpoints that are enabled by default. By communicating directly with the application over the network, an attacker can perform high-impact actions, including reading SMS messages, accessing call logs, extracting contact information, and sending arbitrary SMS messages. Furthermore, the vulnerability exposes a 'clone' API that enables attackers to export or overwrite the application configuration. This impact is significant for environments where SmsForwarder is used to bridge messaging services or automate communication, as the exposed functionality effectively grants an attacker full control over the mobile device's communication capabilities.

## Impact

The vulnerability poses a severe risk of data exfiltration and unauthorized command execution for users of SmsForwarder. Attackers can monitor private communications, spoof legitimate messages, and gain persistence or modify the application behavior by overwriting configurations. This is particularly dangerous for enterprise users relying on the software for secure SMS forwarding or secondary authentication channels, where interception or manipulation could lead to account takeovers or sensitive data leaks.

## Recommendation

* Upgrade SmsForwarder to a version beyond 3.5.0 immediately to address the insecure AndServer implementation.
* Restrict network access to the mobile device running SmsForwarder, ensuring that the port used by the AndServer component is not exposed to untrusted or public networks.
* Audit mobile device firewall settings and application permissions to identify and isolate instances of SmsForwarder exposed to network segments accessible by unauthorized third parties.
