---
title: Russian-Linked Clusters Abuse Authentication Flows for Targeted Credential Theft
slug: 2026-08-russian-auth-flow-abuse
description: Suspected Russian threat clusters UNC6293 and UNC7005 are abusing legitimate OAuth, app password, and device code authentication workflows to bypass MFA and compromise high-value targets in academia, government, and defense.
date: "2026-08-20T19:09:58Z"
type: threat
types:
  - threat
severities:
  - high
actors:
  - ICE RELIC
tags:
  - phishing
  - credential-theft
  - oauth
  - espionage
  - ice-relic
vendors:
  - Microsoft
  - Meta
products:
  - Microsoft Account
  - WhatsApp
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: These clusters engage in persistent, adaptive phishing campaigns, using sophisticated social engineering tactics to compromise personal accounts across multiple platforms.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: In cases of app password phishing, attackers attempt to convince targets to set specific app passwords on their accounts.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: By providing the requested verification code the target would grant UNC6293 access to the account.
    confidence_band: high
references:
  - https://cloud.google.com/blog/topics/threat-intelligence/distinct-clusters-target-individuals-of-interest-to-russia/
iocs:
  - type: domain
    value: foreignrelations.us
ioc_counts:
  domain: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Block foreignrelations.us on all corporate DNS resolvers
      owner: SOC
      due: 24h
      evidence: Identified as UNC6293 infrastructure
  enrichment_needed:
    - item: Additional domains associated with UNC7005
      owner: CTI
      reason: UNC7005 infrastructure is frequently rotated
      evidence: Infrastructure with divergent characteristics observed
  hunt_leads:
    - lead: Audit Azure AD logs for suspicious OAuth application grants to unknown or external applications
      technique_id: T1528
      data_needed:
        - Azure AD sign-in/audit logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: OAuth phishing observed in June 2026
  mitigation_plan:
    - priority: immediate
      action: Disable legacy authentication protocols and app-specific password support
      owner: IT Operations
      addresses: T1552.001
      evidence: App password phishing specifically targets these bypasses
---

Google Threat Intelligence Group (GTIG) has identified two distinct threat clusters, UNC6293 and UNC7005, actively targeting individuals in academia, aerospace, defense, and government sectors across Europe and the United States. These clusters, assessed as operating under the broader ICE RELIC (formerly APT29) umbrella, leverage sophisticated social engineering to manipulate legitimate authentication workflows. By impersonating government officials or conference organizers, the attackers trick targets into generating app-specific passwords, performing OAuth consent grants, or providing device activation codes. These techniques effectively circumvent multi-factor authentication (MFA) by tricking the user into granting the attacker authorized access to their accounts. While UNC6293 demonstrates a more refined operational security and focus on diplomatic themes, UNC7005 has been observed using similar tactics alongside malware delivery. These operations are typically small-scale and highly targeted, focusing on high-value individuals critical of Russian state policy.

## Attack Chain

1. The attacker conducts reconnaissance to identify individuals of interest within academia, defense, or government sectors.
2. The attacker crafts a lure, such as a PDF or email, impersonating a reputable entity (e.g., U.S. State Department, GLOBSEC).
3. The attacker hosts a spoofed landing page (e.g., at foreignrelations[.]us) designed to facilitate a specific authentication flow.
4. The victim is directed to the malicious site through spearphishing, where they are prompted to initiate an authentication process.
5. The victim is coerced into performing a specific action: creating an app password, performing an OAuth token request, or generating a device code.
6. The victim provides the resulting sensitive credential (app password, code, or OAuth URL) to the attacker via a web form or email.
7. The attacker uses the obtained credential to authenticate to the target's account, bypassing MFA requirements.
8. The attacker gains unauthorized access to the victim's data, such as emails, contacts, or documents, for espionage purposes.

## Impact

Successful compromise of these accounts allows for the exfiltration of sensitive diplomatic, academic, and defense-related intelligence. By bypassing MFA, the attackers gain long-term, stealthy access to personal and institutional communication channels. These campaigns have been observed targeting prominent critics of the Russian state, with the potential to influence policy and disrupt organizational operations.

## Recommendation

* Implement Conditional Access policies to restrict or block the creation and use of legacy app-specific passwords where possible.
* Audit and restrict the ability of users to grant OAuth permissions to unverified third-party applications.
* Train staff on the risks of device code phishing, emphasizing that they should never share authorization codes with anyone.
* Block traffic to the known malicious domain foreignrelations[.]us at the organization's network perimeter.
* Deploy identity-focused monitoring to detect anomalous sign-ins occurring immediately after a user has performed an authentication action on an external site.
