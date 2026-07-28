---
title: 'Erlang/OTP: Multiple Vulnerabilities'
slug: 2026-07-erlang-otp-multiple-vulnerabilities
description: Multiple vulnerabilities in Erlang/OTP allow a remote, anonymous attacker to perform a Denial of Service attack, execute arbitrary code, bypass security measures, and manipulate or disclose data.
date: "2026-07-28T10:26:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - erlang
  - otp
  - rce
  - dos
  - data-exfiltration
  - defense-evasion
vendors:
  - Ericsson
products:
  - Erlang/OTP
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: beliebigen Code auszuführen
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Transpiration/Energy Disruption
    evidence: Denial of Service Angriff durchzuführen
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2533
---

A remote, anonymous attacker can exploit multiple unspecified vulnerabilities within the Erlang/OTP framework, which is widely used in telecommunications, distributed systems, and messaging applications. These vulnerabilities pose a critical risk, enabling adversaries to conduct Denial of Service attacks, execute arbitrary code on affected systems, bypass existing security controls, and illicitly manipulate or disclose sensitive data. While the specific versions affected are not detailed in this advisory, the broad scope of potential impact necessitates immediate attention from defenders, particularly those managing critical infrastructure dependent on Erlang/OTP. The advisory highlights the severe implications of unpatched Erlang/OTP instances, making them prime targets for disruption and data compromise.

## Impact

If successfully exploited, these vulnerabilities could lead to significant operational disruption through Denial of Service attacks, potentially crashing critical Erlang/OTP-based services. The ability to execute arbitrary code grants attackers full control over compromised systems, allowing for further lateral movement, persistent access, and the deployment of additional malicious payloads. Bypassing security measures undermines an organization's defense posture, while data manipulation and disclosure can result in severe data integrity issues, regulatory non-compliance, and substantial financial and reputational damage for affected organizations across various sectors.

## Recommendation

* Enable detailed process creation and network connection logging on systems hosting Erlang/OTP to detect anomalous activity.
* Review Erlang/OTP application logs and system event logs for error messages, unexpected restarts, or indicators of data manipulation and unauthorized access attempts.
* Update Erlang/OTP installations to the latest patched versions as soon as they become available from Ericsson to remediate these vulnerabilities.
