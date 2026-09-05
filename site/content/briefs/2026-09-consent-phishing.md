---
title: OAuth Consent Phishing Campaigns Targeting Account Permissions
slug: 2026-09-consent-phishing
description: Malicious actors are using social engineering to lure victims into granting high-level OAuth permissions to attacker-controlled applications, enabling persistent access that bypasses password and multi-factor authentication.
date: "2026-09-02T00:08:08Z"
lastmod: "2026-09-05T17:25:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - phishing
  - oauth
  - account-takeover
  - cloud-security
  - identity
vendors:
  - Microsoft
products:
  - Microsoft 365
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: The user is redirected to a legitimate communication provider permission request screen when they click the malicious link.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: OAuth consent phishing provides actors with persistent access to a target's account because once permission is obtained, it can only be revoked by the victim invalidating the token.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1528
    technique_name: Steal Application Access Token
    evidence: From that moment, the cyber actor can act on behalf of the user, including reading and sending emails, and accessing sensitive data.
    confidence_band: high
references:
  - https://www.ic3.gov/PSA/2026/PSA260901
  - https://www.reddit.com/r/blueteamsec/comments/1w86pnp/malicious_cyber_actors_gain_access_to_victim/
action_plan:
  priority: elevated
  owners:
    - SOC
    - Identity and Access Management
  immediate_actions:
    - action: Review and audit existing OAuth application grants in cloud environments
      owner: Identity and Access Management
      due: 48h
      evidence: OAuth consent phishing provides actors with persistent access to a target's account.
  hunt_leads:
    - lead: Identify new OAuth application grants to non-standard or high-privilege applications
      technique_id: T1528
      data_needed:
        - Identity provider audit logs for application consent events
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The cyber actor can act on behalf of the user... without having access to the user's credentials.
  mitigation_plan:
    - priority: immediate
      action: Configure policies to restrict user-level OAuth application consent for sensitive scopes
      owner: Identity and Access Management
      addresses: T1528
      evidence: Mitigation strategies include... only grant authorization to trusted applications.
updates:
  - at: "2026-09-05T17:25:43Z"
    level: L1
    summary: new product
    sources:
      - reddit-blueteamsec
    source_urls:
      - https://www.reddit.com/r/blueteamsec/comments/1w86pnp/malicious_cyber_actors_gain_access_to_victim/
---

Since late 2025, malicious actors have been leveraging OAuth consent phishing to gain unauthorized access to user accounts. By impersonating government officials, media figures, or event coordinators via commercial messaging applications (CMA), attackers deceive victims into clicking links that lead to legitimate OAuth permission request screens. Unlike credential harvesting, this technique does not require the user's password; instead, it tricks the user into granting a malicious application broad access to their account data, such as email read/write permissions. Once granted, the attacker maintains persistent access to the account even if the victim changes their password. The victim must manually revoke the token through their account security settings to terminate the unauthorized access. This technique effectively bypasses multi-factor authentication (MFA) because the access is authorized via a legitimate service provider protocol.

## Attack Chain

1. Attacker creates a malicious application within a legitimate OAuth-enabled platform.
2. Attacker performs reconnaissance to identify targets and establishes rapport via a commercial messaging application.
3. Attacker sends a phishing message impersonating a trusted entity to the target.
4. Victim clicks a link provided in the message, which redirects them to a legitimate service provider's OAuth consent screen.
5. The OAuth screen prompts the victim to grant specific permissions (e.g., read email, access files) to the attacker-controlled application.
6. Victim approves the consent request, unknowingly granting the attacker an access token.
7. Attacker utilizes the granted token to access the victim's account, exfiltrate data, or send further phishing messages from the compromised account.
8. Attacker maintains persistence by keeping the authorized application active in the account's security settings.

## Impact

Victims targeted include prominent individuals, family members, and personal acquaintances. Successful exploitation results in persistent, unauthenticated access to sensitive data and the ability for the attacker to communicate on behalf of the victim. Because access is granted at the application level, standard security measures like password resets or MFA do not remove the adversary's access, leading to long-term compromise of account communications and associated cloud data.

## Recommendation

Prioritize defensive efforts to audit and restrict OAuth applications and monitor for unauthorized token grants.

- Implement an enterprise OAuth application policy to restrict or require administrative approval for users to grant permissions to new or unverified third-party applications.
- Review current OAuth application permissions in SaaS/cloud environments to identify and revoke access for suspicious, unused, or unauthorized applications.
- Educate users on the distinction between entering credentials and granting application-level access permissions.
- Monitor logs for unusual OAuth grant events, specifically focusing on applications with high-privilege scopes (e.g., Mail.Read, Mail.Send, Files.ReadWrite) granted to non-standard or external publishers.
