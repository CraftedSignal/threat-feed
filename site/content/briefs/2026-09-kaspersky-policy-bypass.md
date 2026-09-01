---
title: Security Policy Bypass in Kaspersky Endpoint Security for Windows
slug: 2026-09-kaspersky-policy-bypass
description: A security policy bypass vulnerability exists in Kaspersky Endpoint Security for Windows, affecting versions 14.0 and 14.1, which allows attackers to circumvent configured security enforcement.
date: "2026-09-01T17:59:18Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
tags:
  - vulnerability
  - security-policy-bypass
vendors:
  - Kaspersky
products:
  - Endpoint Security Windows (14.0, 14.1 < 2026-08-30)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Elle permet à un attaquant de provoquer un contournement de la politique de sécurité.
    confidence_band: high
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1101/
  - https://support.kaspersky.com/vulnerability/list-of-advisories/12430#310826
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Deploy security update dated 2026-08-30 to all Endpoint Security Windows 14.0/14.1 instances.
      owner: IT Operations
      due: 48h
      evidence: Source advisory CERTFR-2026-AVI-1101
  mitigation_plan:
    - priority: immediate
      action: Upgrade to the patched version defined in Kaspersky advisory 12430#310826.
      owner: IT Operations
      addresses: Endpoint Security Windows policy bypass
      evidence: Kaspersky security bulletin 12430#310826
---

A security vulnerability has been identified in Kaspersky Endpoint Security for Windows that allows an attacker to bypass established security policies. The flaw affects versions 14.0 and 14.1 of the application that have not applied the security update released on August 30, 2026. This vulnerability is significant as it potentially permits the subversion of security controls, enabling unauthorized system activity that would otherwise be blocked by the agent. Defenders must ensure all instances of the affected versions are patched according to the vendor's guidance to maintain endpoint integrity and policy enforcement.

## Impact

Successful exploitation of this vulnerability allows an attacker to circumvent configured security policies on the targeted endpoint. This impacts the ability of the security software to provide protection, increasing the risk of further malicious activity, unauthorized access, or persistence that would typically be prevented by the security agent.

## Recommendation

Prioritize the deployment of the security update released on August 30, 2026, for all instances of Kaspersky Endpoint Security for Windows 14.0 and 14.1. Audit the environment to identify any endpoints running these specific legacy versions and ensure they are patched immediately.
