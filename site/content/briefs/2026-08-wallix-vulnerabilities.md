---
title: Multiple Security Vulnerabilities in Wallix Access Manager and Bastion
slug: 2026-08-wallix-vulnerabilities
description: Multiple vulnerabilities in Wallix Access Manager and Bastion products allow for unauthorized privilege escalation and security policy bypass.
date: "2026-08-06T15:19:26Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - privilege-escalation
  - authentication-bypass
  - informational
vendors:
  - Wallix
products:
  - Access Manager
  - Bastion
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Elles permettent à un attaquant de provoquer une élévation de privilèges
    confidence_band: high
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0974/
  - https://www.wallix.com/support-services/alerts/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch all vulnerable instances of Wallix Access Manager and Bastion
      owner: IT Operations
      due: 48h
      evidence: CERT-FR advisory recommends referring to editor security bulletin
  mitigation_plan:
    - priority: immediate
      action: Review SAML federation configuration for affected Access Manager versions
      owner: IT Operations
      addresses: Access Manager SAML federation vulnerability
      evidence: Advisory notes Access Manager with SAML federation as specifically affected
---

The French National Cybersecurity Agency (ANSSI) has published an advisory regarding multiple vulnerabilities identified in Wallix Access Manager and Bastion products. These flaws, detailed in the Wallix security bulletin from July 20, 2026, enable an attacker to perform privilege escalation or bypass security policy enforcement mechanisms. The vulnerabilities specifically affect deployments of Wallix Access Manager utilizing SAML federation, as well as specific version branches of the Wallix Bastion. Because these products serve as centralized gateways for privileged access, successful exploitation could provide an attacker with unauthorized administrative control over managed assets. Defenders are urged to audit version numbers against the affected ranges and apply vendor-provided patches immediately.

## Impact

Successful exploitation of these vulnerabilities allows unauthorized actors to escalate privileges within the Wallix management environment and circumvent security policies designed to restrict access. This poses a high risk to organizations relying on Wallix for privileged account management and session recording, as it could allow attackers to bypass audit controls or gain administrative access to critical infrastructure managed by the bastion.

## Recommendation

- Update Wallix Access Manager to version 5.1.10, 5.2.7, or 6.0.4 or later, depending on the current branch.
- Update Wallix Bastion to version 12.3.7 or 12.4.1 or later.
- Review configurations of SAML federation in Access Manager to ensure security controls are correctly enforced until patching is complete.
- Monitor logs for unusual administrative login activity or unauthorized configuration changes on Wallix appliances.
