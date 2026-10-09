---
title: Local Privilege Escalation Vulnerability in Zammad
slug: 2026-10-zammad-privilege-escalation
description: A local attacker can exploit a vulnerability in Zammad to perform privilege escalation on the host system.
date: "2026-10-09T12:52:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - vulnerability
  - local-access
vendors:
  - Zammad
products:
  - Zammad
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A local attacker can exploit a vulnerability in Zammad to perform privilege escalation.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3839
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Review local access control policies on all Zammad-hosting servers.
      owner: IT Operations
      due: 48h
      evidence: Source identifies this as a local privilege escalation vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Update Zammad to the latest vendor-recommended secure version.
      owner: IT Operations
      addresses: General Zammad privilege escalation vulnerability
      evidence: BSI security advisory recommendation.
---

The BSI (German Federal Office for Information Security) has identified a vulnerability in Zammad that allows a local attacker to escalate their privileges. The vulnerability is contingent upon the attacker already possessing local access to the server hosting the Zammad instance. By leveraging this flaw, a local user can bypass standard security controls to achieve higher-level system permissions. This represents a risk to organizations that have not restricted local system access or that rely on Zammad as a service with shared-user environments. Defenders should ensure that the principle of least privilege is applied to all system users and that Zammad service accounts are hardened against local lateral movement and escalation attempts.

## Impact

Successful exploitation allows a local user to obtain elevated privileges on the host operating system. This could lead to full system compromise, unauthorized access to sensitive helpdesk data, or the ability to manipulate the Zammad application and its underlying data stores.

## Recommendation

- Ensure Zammad is updated to the latest available version provided by the vendor to address security defects.
- Apply the principle of least privilege for all local system accounts with access to the Zammad server.
- Restrict local shell access to the server solely to authorized administrators to mitigate the risk of local privilege escalation.
- Audit existing local user accounts and groups on the server to ensure no unauthorized persistence or escalation vectors exist.
