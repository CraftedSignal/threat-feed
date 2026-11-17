---
brief_id: brief-2026-11-17-pkinit-u2u-credential-access
event_id: brief-2026-11-17-pkinit-u2u-credential-access
revision: 1
activity_at: "2026-11-17T14:58:13Z"
title: PKINIT Followed by Same-Principal U2U Service Ticket
slug: 2026-11-pkinit-u2u-credential-access
description: This detection identifies a sequence of Kerberos authentication events where a PKINIT ticket request is followed within five seconds by a same-principal user-to-user service ticket request, a pattern consistent with the UnPAC-the-Hash attack technique.
date: "2026-11-17T14:58:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - 'Domain: Identity'
  - 'Platform: Windows'
  - 'OS: Windows'
  - 'Use Case: Threat Detection'
  - 'Tactic: Credential Access'
  - 'Rule Type: Event Correlation (EQL)'
  - 'Use Case: Active Directory Monitoring'
  - 'Data Source: Active Directory'
  - 'Data Source: Windows Security Event Logs'
  - 'Resources: Investigation Guide'
  - 'Noise: Unknown'
  - 'Performance: Normal'
  - 'Domain: Endpoint'
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1558
    technique_name: Steal or Forge Kerberos Tickets
    evidence: This sequence is consistent with the KDC-visible ticket requests used in an UnPAC-the-Hash attack.
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/windows/credential_access_pkinit_same_principal_u2u.toml
  - https://specterops.io/blog/2026/06/09/user-to-user-authentication-down-the-rabbit-hole-part-1/
  - https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/#obtaining-the-nt-hash-of-the-impersonated-computer-account
  - https://github.com/FalconForceTeam/FalconFriday/blob/c662a6a0dc5d973beb3abb673d4e8cdc193bf469/0xFF-0299-UnPAC_the_hash-Win.md
  - https://gist.github.com/H0j3n/a5ef2609b5f2944ac2390a191a534c26
  - https://github.com/dirkjanm/PKINITtools/blob/0f0cfa542b0348609ad494713e84744234b2d3b0/getnthash.py
action_plan:
  hunt_leads:
    - lead: Identify potential UnPAC-the-Hash activity by searching for sequences where a successful PKINIT authentication (Event 4768, PreAuthType 16) is followed within 5 seconds by a User-to-User (U2U) service ticket request (Event 4769) from the same source IP and Domain Controller, where the account principal SID from the initial authentication matches the Service SID in the U2U request.
      technique_id: T1558
      data_needed:
        - winlog.computer_name
        - source.ip
        - event.code
        - winlog.event_data.PreAuthType
        - winlog.event_data.Status
        - winlog.event_data.TargetSid
        - winlog.event_data.ServiceSid
        - winlog.event_data.TicketOptions
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: This sequence is consistent with the KDC-visible ticket requests used in an UnPAC-the-Hash attack, before client-side PAC credential decryption and NT hash recovery.
---

## Overview
This rule identifies a successful PKINIT ticket-granting ticket request (event 4768, PreAuthType 16) followed within five seconds on the same domain controller and source address by a successful user-to-user (U2U) service-ticket request (event 4769, TicketOptions 0x40810008 or 0x40810018), where the service SID matches the PKINIT principal SID. This pattern is consistent with the KDC-visible ticket requests used in an UnPAC-the-Hash attack before client-side PAC credential decryption and NT hash recovery. The certificate used for PKINIT may have been obtained through CertiGhost or another certificate-abuse path.

## Attack Chain
1. A successful PKINIT TGT request (4768) occurs.
2. Within five seconds, a successful U2U service ticket request (4769) occurs from the same source IP and computer.
3. The 4769 service SID matches the 4768 principal SID.

## Impact
This activity is consistent with UnPAC-the-Hash, which may be used for credential recovery.

## Recommendation
- Enable 'Audit Kerberos Authentication Service' and 'Audit Kerberos Service Ticket Operations' on domain controllers.
- Investigate by resolving the 4769 requester name and domain against the 4768 principal to confirm identity.
- If the client endpoint is identified, collect volatile process or memory evidence before isolation.
