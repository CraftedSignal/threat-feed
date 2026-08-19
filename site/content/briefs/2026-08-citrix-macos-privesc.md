---
title: Citrix Workspace App for macOS Privilege Escalation Vulnerability
slug: 2026-08-citrix-macos-privesc
description: A local privilege escalation vulnerability in Citrix Workspace App for macOS allows a local attacker to elevate their system permissions.
date: "2026-08-19T16:33:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - macos
  - endpoint-security
vendors:
  - Citrix
products:
  - Workspace App
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A local attacker can exploit a vulnerability in Citrix Systems Workspace App (MacOS) to escalate their privileges.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2917
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Citrix Workspace App on all managed macOS devices.
      owner: IT Operations
      addresses: Privilege escalation vulnerability in Citrix Workspace App
      evidence: BSI advisory WID-SEC-2026-2917
---

The BSI has released an advisory regarding a security vulnerability in Citrix Workspace App for macOS. The vulnerability allows a local attacker to escalate their privileges to a higher level than intended. This typically occurs when a local user account on the target machine leverages flaws in the application installation or update process, or through insecure inter-process communication mechanisms. Given that Citrix Workspace App is a standard deployment in many enterprise environments, this vulnerability presents a risk to endpoint security, potentially allowing an attacker who has already gained low-privileged access to the system to achieve root or system-level administrative control. Organizations are advised to update to the latest version of Citrix Workspace App provided by the vendor to remediate this issue.

## Impact

Successful exploitation of this vulnerability enables a local user to execute commands with elevated privileges, bypassing system security controls. This can result in full system compromise, the potential installation of persistence mechanisms, and unauthorized access to sensitive data stored on the affected macOS workstation. The scope of impact is limited to the macOS ecosystem, specifically targeting endpoints with Citrix Workspace App installed.

## Recommendation

Prioritize the deployment of the latest security patches for Citrix Workspace App across all macOS endpoints.
