---
title: Critical OS Command Injection in Haiwell IoT Cloud HMI Gateway
slug: 2026-08-haiwell-hmi-rce
description: An unauthenticated OS command injection vulnerability in the Haiwell IoT Cloud HMI Gateway allows attackers to achieve arbitrary command execution with root privileges via the Net Check feature.
date: "2026-08-13T16:53:17Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - ics
  - rce
  - cve-2026-19188
  - critical-infrastructure
vendors:
  - Haiwell
products:
  - Haiwell IoT Cloud HMI Gateway (3.40.1.12)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability exists in the Net Check feature accessible via the /setting endpoint, allowing an unauthenticated attacker to inject and execute arbitrary OS commands.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The cmdPing Socket.io event fails to properly sanitize user-supplied input before passing it to the underlying operating system.
    confidence_band: high
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-225-02
  - https://www.cve.org/CVERecord?id=CVE-2026-19188
rules:
  - title: Detects CVE-2026-19188 Exploitation - Command Injection via Socket.io
    description: Detects potential exploitation attempts against the Haiwell HMI Gateway Net Check feature by monitoring for shell metacharacters in traffic targeting the /setting endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all Haiwell IoT Cloud HMI Gateway devices and verify firmware version.
      owner: IT Operations
      due: 24h
      evidence: Product version 3.40.1.12 is vulnerable.
    - action: Deploy WAF or network filtering rules to block malicious payloads targeting /setting.
      owner: SOC
      due: 24h
      evidence: Vulnerability is located at the /setting endpoint.
  mitigation_plan:
    - priority: immediate
      action: Patch devices to Scada-v3.50.1.19.
      owner: IT Operations
      addresses: CVE-2026-19188
      evidence: Remediation provided in advisory.
---

A critical OS command injection vulnerability (CVE-2026-19188) has been identified in the Haiwell IoT Cloud HMI Gateway, specifically version 3.40.1.12. The vulnerability exists within the 'Net Check' feature accessible via the '/setting' endpoint. An unauthenticated attacker can interact with the 'cmdPing' Socket.io event to pass unsanitized input to the underlying operating system. Because the application runs with root-level privileges, successful exploitation grants the attacker full control over the gateway device. This vulnerability is of particular concern for operators in the energy, critical manufacturing, and water/wastewater sectors where these gateways are deployed to manage industrial control processes.

## Impact

Successful exploitation of this vulnerability results in full system compromise, allowing an attacker to execute arbitrary OS commands as the root user. Given the role of HMI gateways in critical infrastructure, this could lead to unauthorized control of industrial processes, data exfiltration, or complete service disruption. The CVSS score of 10.0 reflects the high risk to both confidentiality, integrity, and availability.

## Recommendation

- Upgrade the Haiwell IoT Cloud HMI Gateway to patch version Scada-v3.50.1.19 immediately.
- Restrict network access to the '/setting' endpoint and the Socket.io interface to authorized internal management IP addresses only.
- Isolate all industrial HMI gateways from the public internet using firewalls and VPNs to prevent remote exploitation of this unauthenticated vector.
- Monitor webserver logs for unexpected POST or WebSocket activity targeting the '/setting' endpoint, particularly those containing shell metacharacters.
