---
title: Multiple Vulnerabilities in Wibu-Systems CodeMeter Runtime
slug: 2026-08-wibu-codemeter
description: Multiple vulnerabilities in Wibu-Systems CodeMeter Runtime allow attackers to bypass security, disclose sensitive data, manipulate information, escalate privileges, or induce denial-of-service conditions.
date: "2026-08-26T14:06:12Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - privilege-escalation
  - dos
vendors:
  - Wibu-Systems
products:
  - CodeMeter Runtime
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An attacker can exploit several vulnerabilities in Wibu-Systems CodeMeter Runtime to escalate privileges and gain administrator rights.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: An attacker can exploit several vulnerabilities in Wibu-Systems CodeMeter Runtime to cause denial-of-service states.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3004
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch CodeMeter Runtime on all hosts
      owner: IT Operations
      due: 72h
      evidence: Vendor security advisory
  mitigation_plan:
    - priority: immediate
      action: Restrict access to CodeMeter service port 22350
      owner: IT Operations
      addresses: CodeMeter Runtime
      evidence: Mitigation for remote exploitation surface
---

Wibu-Systems has reported multiple vulnerabilities affecting the CodeMeter Runtime environment. These vulnerabilities permit unauthenticated or local attackers to perform a variety of malicious actions, ranging from information disclosure and data manipulation to full privilege escalation resulting in administrator-level access. In some configurations, the flaws may be exploited to trigger denial-of-service (DoS) conditions, effectively rendering the licensing service unavailable. The security impact is severe, as CodeMeter Runtime is frequently utilized for software licensing and copy protection across a wide range of enterprise and industrial applications. Defenders should prioritize auditing the exposure of the CodeMeter service and ensuring systems are updated to the latest vendor-provided release.

## Impact

Successful exploitation of these vulnerabilities can lead to full system compromise, unauthorized access to sensitive licensing information, and disruption of critical business software. Organizations running affected versions of CodeMeter Runtime on Windows, Linux, or macOS systems are at risk.

## Recommendation

- Identify all instances of Wibu-Systems CodeMeter Runtime within the environment to assess exposure.
- Apply security patches provided by Wibu-Systems as a priority to mitigate privilege escalation and information disclosure risks.
- Restrict network access to the CodeMeter service (default TCP port 22350) to trusted hosts only, reducing the potential attack surface for remote exploitation.
