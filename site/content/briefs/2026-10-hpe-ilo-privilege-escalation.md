---
title: HPE Integrated Lights-Out Privilege Escalation Vulnerability
slug: 2026-10-hpe-ilo-privilege-escalation
description: A vulnerability in HPE Integrated Lights-Out (iLO) allows a remote, unauthenticated attacker to escalate privileges, posing a risk of unauthorized administrative access to server hardware.
date: "2026-10-06T12:42:44Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:hewlett_packard_enterprise:integrated_lights_out:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - hardware-security
  - vulnerability
vendors:
  - Hewlett Packard Enterprise
products:
  - Integrated Lights-Out
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A vulnerability in HPE Integrated Lights-Out (iLO) allows a remote, unauthenticated attacker to escalate privileges.
    confidence_band: high
cves:
  - id: CVE-2024-21820
    cvss: 7.2
    epss: 0.00216
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3756
action_plan:
  priority: elevated
  owners:
    - Infrastructure Operations
    - SOC
  immediate_actions:
    - action: Patch CVE-2024-21820 on all HPE iLO devices
      owner: Infrastructure Operations
      due: 72h
      evidence: Source advisory specifies privilege escalation vulnerability requiring firmware update.
  mitigation_plan:
    - priority: immediate
      action: Isolate iLO management interfaces from non-management network segments
      owner: Network Security
      addresses: CVE-2024-21820
      evidence: Reduction of attack surface for remote, unauthenticated access.
---

Hewlett Packard Enterprise (HPE) has identified a vulnerability in Integrated Lights-Out (iLO) firmware that enables a remote, unauthenticated attacker to perform privilege escalation. This security flaw, identified as CVE-2024-21820, targets the management processor responsible for out-of-band server management. Successful exploitation allows an attacker to bypass authentication or elevate privileges to administrative levels, granting them complete control over the compromised server hardware. This level of access bypasses traditional OS-level security controls and allows for persistent, low-level system modifications, such as firmware tampering, hardware power control, and access to the server console. Organizations utilizing HPE server hardware with iLO management interfaces should prioritize updating to the latest vendor-provided firmware versions to mitigate the risk of unauthorized administrative access.

## Impact

Successful exploitation allows a remote attacker to gain administrative control over the iLO interface. This results in the ability to modify server firmware, alter boot configurations, intercept system console traffic, and gain persistent unauthorized access to the underlying server hardware regardless of the operating system's security state.

## Recommendation

Prioritized, concrete actions for infrastructure and security teams:
- Identify all HPE iLO management interfaces reachable across the network, particularly those exposed to internet or untrusted segments.
- Patch CVE-2024-21820 by upgrading all affected HPE iLO firmware components to the vendor-recommended secure version.
- Restrict access to iLO management interfaces to dedicated, isolated management networks and implement multi-factor authentication (MFA) for administrative access.
