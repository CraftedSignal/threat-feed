---
title: Local Privilege Escalation in Sophos Endpoint
slug: 2026-08-sophos-endpoint-privesc
description: A local privilege escalation vulnerability in Sophos Endpoint allows an authenticated local attacker to execute arbitrary code with administrative privileges.
date: "2026-08-07T09:20:28Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - windows
  - security-advisory
vendors:
  - Sophos
products:
  - Endpoint
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein lokaler Angreifer kann eine Schwachstelle in Sophos Endpoint ausnutzen, um seine Privilegien zu erhöhen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2690
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory Sophos Endpoint versions and plan emergency patching
      owner: IT Operations
      due: 48h
      evidence: Vendor advisory regarding local privilege escalation vulnerability
---

Sophos has disclosed a security vulnerability affecting Sophos Endpoint software that permits a local attacker to perform privilege escalation. This vulnerability allows an attacker who already possesses local access to the target system to elevate their permissions to administrative level. Upon successful exploitation, the attacker can execute arbitrary code with SYSTEM or Administrator privileges. This flaw poses a significant risk to organizational security, as it bypasses standard access control mechanisms. Defenders should prioritize identifying systems running vulnerable versions of Sophos Endpoint and ensure they are patched to the latest version provided by the vendor. This is a local vector, meaning the attacker must first establish a foothold on the endpoint through other means.

## Impact

Successful exploitation of this vulnerability results in full administrative compromise of the affected host. This allows an attacker to disable security controls, deploy malware, exfiltrate sensitive data, or establish persistence at the highest privilege level. The impact is critical for any endpoint where a threat actor has achieved initial low-privileged access.

## Recommendation

* Monitor security bulletins from Sophos for the release of patches addressing this privilege escalation vulnerability and apply them immediately.
* Audit systems for unauthorized local user accounts or recent privilege elevation activities that could indicate an attacker is attempting to exploit such vulnerabilities.
* Limit local administrative rights to the minimum set required for business operations to reduce the potential impact of local privilege escalation.
